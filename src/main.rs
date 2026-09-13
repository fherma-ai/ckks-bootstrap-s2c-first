//! WRAPPER — the harness around `init` / `generate` / `run` / `digest`. The same shape as
//! the generated `main.rs` of every Poulpy solution on the platform:
//!
//!     ./fherma-solution <point directory>
//!
//! reads the directory a bundle prepared, answers every case in it, and writes
//! what each stage cost. Every stage is timed — `init` (keygen), `generate`
//! (the case from its seed), the warm-up, `run`, `digest` (serialising the
//! output), writing it, `check` (decrypting it for its precision) — and only
//! the call to `run::run` is the score; the rest is reported beside it, so a
//! reader sees the whole cost and a challenge can choose what it counts.
//!
//! The point directory:
//!
//!     manifest.json            {"N": 65536, "log_delta": 35, "output_k": 720, "key_seed": 0, "cases": 100}
//!     config.jsonc             optional overlay of the solution's own (threads)
//!     cases/000017/case_seed.bin   one u64, little-endian — the whole input
//!     out/000017/ct.bin        the output ciphertext, canonical bytes (written here)
//!     out/results.json         init_s, warmup_s, one row per case with every stage's
//!                              seconds and the precision metrics, max_rss_bytes (written here)
//!
//! Correctness is the platform's: sha256(out/NNNNNN/ct.bin) against the
//! expected digest the reference produced for the same point and seed. The
//! row carries the same digest, for reading by eye.
//!
//!     ./fherma-solution make <dir> --point '{"N":65536,"log_delta":35,"output_k":720,"key_seed":0}' --seeds 1,2,3
//!
//! writes such a directory: the bundle's own `make` interface, so the same
//! binary can stand in for the bundle locally. Case i holds seeds[i].

mod backend;
mod check;
mod digest;
mod fherma;
mod generate;
mod init;
mod run;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use fherma::{Inputs, Point};

type Anyhow<T> = Result<T, Box<dyn std::error::Error>>;

/// Discarded runs before the first timed one.
const WARMUP: usize = 3;

fn main() -> Anyhow<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("make") => make(&args[1..]),
        Some(dir) if args.len() == 1 => solve(Path::new(dir)),
        _ => {
            eprintln!("usage: fherma-solution <point directory>");
            eprintln!("       fherma-solution make <dir> --point '{{\"N\":65536,\"log_delta\":35,\"output_k\":720,\"key_seed\":0}}' --seeds 1,2,3");
            std::process::exit(2)
        }
    }
}

fn solve(root: &Path) -> Anyhow<()> {
    let manifest = fs::read_to_string(root.join("manifest.json"))?;
    let point = point_of(&manifest)?;
    let total = number(&manifest, "cases")? as usize;
    // Refuse a point this specification has no preset for before doing any work.
    let preset = init::preset_for(&point)?;

    // The config travels with the solution, not the point; the point's own
    // copy wins when a runner lays one there.
    let config_path = if root.join("config.jsonc").exists() {
        root.join("config.jsonc")
    } else {
        PathBuf::from("config.jsonc")
    };
    let threads = threads_from_config(&config_path);

    let out_root = root.join("out");
    fs::create_dir_all(&out_root)?;

    // INIT: keygen from the point's key-seed. Once. Not measured; reported apart.
    let setup = Instant::now();
    let mut state = init::State::init(&point);
    let init_s = setup.elapsed().as_secs_f64();

    let head = format!(
        "\"point\":{{\"N\":{},\"log_delta\":{},\"output_k\":{},\"key_seed\":{}}},\"preset\":\"{}\",\"poulpy\":\"{}\",\"backend\":\"{}\",\"threads\":{threads},\"warmup\":{WARMUP}",
        point.N, point.log_delta, point.output_k, point.key_seed, preset.name(), init::POULPY_VERSION, backend::NAME
    );
    let mut rows: Vec<String> = Vec::new();
    let mut warmup_s = 0.0f64;
    report(&out_root, &head, init_s, warmup_s, &rows);

    let mut warmed = false;
    for i in 0..total {
        let case_dir = root.join("cases").join(format!("{i:06}"));
        let answer_dir = out_root.join(format!("{i:06}"));

        let input = match inputs_of(&case_dir) {
            Ok(input) => input,
            Err(failure) => {
                rows.push(crashed_row(i, &format!("reading the case: {failure}")));
                report(&out_root, &head, init_s, warmup_s, &rows);
                continue;
            }
        };
        let case_seed = input.case_seed;

        // GENERATE: the case from its input. Timed apart.
        let mark = Instant::now();
        let case = generate::generate(&mut state, &input);
        let generate_s = mark.elapsed().as_secs_f64();

        // WARM-UP: discarded runs before the first timed one. Timed as a whole.
        if !warmed {
            let mark = Instant::now();
            for _ in 0..WARMUP {
                run::run(&mut state, &case.input);
            }
            warmup_s = mark.elapsed().as_secs_f64();
            warmed = true;
        }

        // RUN: monotonic, and around the call and nothing else. The score.
        let started = Instant::now();
        run::run(&mut state, &case.input);
        let seconds = started.elapsed().as_secs_f64();

        // DIGEST: the output as canonical bytes, and its hash.
        let mark = Instant::now();
        let bytes = digest::bytes(&state.output);
        let sha = digest::sha256(&bytes);
        let digest_s = mark.elapsed().as_secs_f64();

        // WRITE: the bytes to out/, for the bundle to hash the same way.
        let mark = Instant::now();
        if let Err(failure) = fs::create_dir_all(&answer_dir).and_then(|_| fs::write(answer_dir.join("ct.bin"), &bytes))
        {
            rows.push(crashed_row(i, &format!("writing the answer: {failure}")));
            report(&out_root, &head, init_s, warmup_s, &rows);
            continue;
        }
        let write_s = mark.elapsed().as_secs_f64();

        // CHECK: decrypt and measure against the message. A metric, not the score.
        let mark = Instant::now();
        let precision = check::precision(&mut state, &case.re, &case.im);
        let check_s = mark.elapsed().as_secs_f64();

        rows.push(format!(
            concat!(
                "{{\"i\":{i},\"seconds\":{seconds:.9},\"status\":\"ok\",\"case_seed\":{case_seed},",
                "\"generate_s\":{generate_s:.9},\"digest_s\":{digest_s:.9},\"write_s\":{write_s:.9},\"check_s\":{check_s:.9},",
                "\"digest\":\"{sha}\",",
                "\"metrics\":{{\"precision_bits\":{pmin:.3},\"precision_bits_avg\":{pavg:.3},",
                "\"precision_bits_re\":{pre:.3},\"precision_bits_im\":{pim:.3},\"max_abs_err\":{err:.3e}}}}}"
            ),
            i = i,
            seconds = seconds,
            case_seed = case_seed,
            generate_s = generate_s,
            digest_s = digest_s,
            write_s = write_s,
            check_s = check_s,
            sha = sha,
            pmin = precision.re_min_bits.min(precision.im_min_bits),
            pavg = (precision.re_avg_bits + precision.im_avg_bits) / 2.0,
            pre = precision.re_min_bits,
            pim = precision.im_min_bits,
            err = precision.max_abs_err,
        ));
        report(&out_root, &head, init_s, warmup_s, &rows);
    }
    Ok(())
}

/// Written after every case, not at the end: a process killed on its timeout
/// has still done the cases before it.
fn report(out: &Path, head: &str, init_s: f64, warmup_s: f64, rows: &[String]) {
    let body = format!(
        "{{{head},\"init_s\":{init_s:.9},\"warmup_s\":{warmup_s:.9},\"max_rss_bytes\":{},\"cases\":[{}]}}",
        max_rss_bytes(),
        rows.join(",")
    );
    let _ = fs::write(out.join("results.json"), body);
}

fn crashed_row(i: usize, why: &str) -> String {
    let clean: String = why
        .chars()
        .take(200)
        .map(|c| if c == '"' || c == '\\' || c == '\n' { ' ' } else { c })
        .collect();
    format!("{{\"i\":{i},\"seconds\":null,\"status\":\"crashed\",\"note\":\"{clean}\"}}")
}

/// Size the rayon pool from `config.jsonc` (`threads`); the single-thread
/// backends ignore it and report 1.
fn threads_from_config(path: &Path) -> usize {
    if !backend::THREADED {
        return 1;
    }
    let all = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let wanted = fs::read_to_string(path)
        .ok()
        .and_then(|text| number(&strip_comments(&text), "threads").ok())
        .map(|t| t as usize)
        .filter(|&t| t > 0)
        .unwrap_or(all);
    backend::set_threads(wanted);
    wanted
}

fn strip_comments(text: &str) -> String {
    text.lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

fn number(text: &str, key: &str) -> Anyhow<f64> {
    let quoted = format!("\"{key}\"");
    let at = text.find(&quoted).ok_or_else(|| format!("no {key}"))?;
    let colon = text[at..].find(':').ok_or("malformed json")? + at;
    let rest = text[colon + 1..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '-' && c != '.' && c != 'e')
        .unwrap_or(rest.len());
    Ok(rest[..end].parse()?)
}

/// The point as `manifest.json` (or `--point`) states it: the signature's
/// `Point`, one field per parameter.
fn point_of(text: &str) -> Anyhow<Point> {
    Ok(Point {
        N: number(text, "N")? as u32,
        log_delta: number(text, "log_delta")? as u32,
        output_k: number(text, "output_k")? as u32,
        key_seed: number(text, "key_seed")? as u64,
    })
}

/// The case as the bundle wrote it: the signature's `Inputs`, one file per
/// argument, little-endian.
fn inputs_of(dir: &Path) -> Anyhow<Inputs> {
    Ok(Inputs { case_seed: read_u64(dir, "case_seed")? })
}

fn read_u64(dir: &Path, name: &str) -> Anyhow<u64> {
    let raw = fs::read(dir.join(format!("{name}.bin")))?;
    let bytes: [u8; 8] = raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("{name}: {} bytes for one u64", raw.len()))?;
    Ok(u64::from_le_bytes(bytes))
}

/// Peak resident memory of this process, in bytes: the RAM a runner must
/// have for this benchmark point.
fn max_rss_bytes() -> u64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } != 0 {
        return 0;
    }
    let v = ru.ru_maxrss as u64;
    if cfg!(target_os = "macos") {
        v
    } else {
        v * 1024
    } // macOS reports bytes, Linux kilobytes
}

/// A point directory, the way the bundle's `make` writes one: the manifest
/// carries the point's parameters and the case count; case i holds seeds[i].
fn make(args: &[String]) -> Anyhow<()> {
    let (mut dir, mut point, mut seeds) = (None, None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--point" => point = it.next().cloned(),
            "--seeds" => seeds = it.next().cloned(),
            _ if dir.is_none() => dir = Some(a.clone()),
            _ => return Err(format!("unexpected argument {a}").into()),
        }
    }
    let (Some(dir), Some(point), Some(seeds)) = (dir, point, seeds) else {
        return Err(
            "make <dir> --point '{\"N\":65536,\"log_delta\":35,\"output_k\":720,\"key_seed\":0}' --seeds 1,2,3".into(),
        );
    };
    let point = point_of(&point)?;
    init::preset_for(&point)?; // a point without a preset is not a point of this spec
    let seeds: Vec<u64> = seeds.split(',').map(|s| s.trim().parse()).collect::<Result<_, _>>()?;

    let root = Path::new(&dir);
    for (i, seed) in seeds.iter().enumerate() {
        let case_dir = root.join("cases").join(format!("{i:06}"));
        fs::create_dir_all(&case_dir)?;
        fs::write(case_dir.join("case_seed.bin"), seed.to_le_bytes())?;
    }
    fs::write(
        root.join("manifest.json"),
        format!(
            "{{\"N\":{},\"log_delta\":{},\"output_k\":{},\"key_seed\":{},\"cases\":{}}}\n",
            point.N,
            point.log_delta,
            point.output_k,
            point.key_seed,
            seeds.len()
        ),
    )?;
    println!("{}: {point:?} cases={} seeds={seeds:?}", root.display(), seeds.len());
    Ok(())
}
