// GENERATED for bootstrap/s2c@1.0.0. Do not edit — `--update` rewrites it.
//
// The loop around the envelope and the author's three functions:
//
//     ./fherma-solution <point directory>
//
// reads the directory a bundle prepared, answers every case in it, and writes
// what each stage cost. Every stage is timed — `setup` (the envelope's keys),
// `init` (the author's), `generate` (the case from its inputs), the warm-up,
// `run`, `serialize`, writing, `check` — and only the call to `run::run` is
// the score; the rest is reported beside it.
//
// The point directory:
//
//     manifest.json             the point's parameters and "cases": how many
//     config.jsonc              optional overlay of the solution's own config
//     cases/000017/<arg>.bin    one file per argument, little-endian, no header
//     out/000017/<result>.bin   one file per result, as the envelope serialises it (written here)
//     out/results.json          setup_s, init_s, warmup_s, one row per case with every stage's
//                               seconds, the metrics, the digest, max_rss_bytes (written here)
//
// Correctness is the platform's: the digest of out/NNNNNN/ — one file, its
// sha256; several, sha256 over `name \0 bytes` of each in name order — against
// what the reference produced, or the envelope's check against the
// specification's thresholds. The row carries the same digest, for reading by eye.
//
//     ./fherma-solution make <dir> --point '{\"N\":0,\"log_delta\":0,\"output_k\":0,\"key_seed\":0}' --seeds 1,2,3
//
// writes such a directory the way the bundle does, for a signature whose
// arguments are seeds. Case i holds seeds[i].

mod envelope;
mod fherma;
mod free;
mod init;
mod run;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use sha2::{Digest, Sha256};

#[allow(unused_imports)]
use fherma::{Inputs, Point, Tensor};

type Anyhow<T> = Result<T, Box<dyn std::error::Error>>;

/// The results the signature declares, in its order. `serialize` must return
/// exactly these, by name.
const RESULTS: &[&str] = &["ct"];

fn main() -> Anyhow<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("make") => make(&args[1..]),
        Some(dir) if args.len() == 1 => solve(Path::new(dir)),
        _ => {
            eprintln!("usage: fherma-solution <point directory>");
            eprintln!("       fherma-solution make <dir> --point '{{\"N\":0,\"log_delta\":0,\"output_k\":0,\"key_seed\":0}}' --seeds 1,2,3");
            std::process::exit(2)
        }
    }
}

fn solve(root: &Path) -> Anyhow<()> {
    let manifest = fs::read_to_string(root.join("manifest.json"))?;
    let point = point_of(&manifest)?;
    let total = number(&manifest, "cases")? as usize;

    // The config travels with the solution, not the point; the point's own
    // copy wins when a runner lays one there.
    let config_path = if root.join("config.jsonc").exists() {
        root.join("config.jsonc")
    } else {
        PathBuf::from("config.jsonc")
    };
    let config = fs::read_to_string(&config_path).unwrap_or_default();

    let out_root = root.join("out");
    fs::create_dir_all(&out_root)?;

    // SETUP: the envelope's — keys, context, public material. Once. Not
    // measured. It sees the solution's config too: a worker pool is built
    // once per process, before any work, and keygen is work.
    let mark = Instant::now();
    let context = envelope::setup(&point, &config);
    let setup_s = mark.elapsed().as_secs_f64();

    // INIT: the author's — over the point and the context, never a case. Not measured.
    let mark = Instant::now();
    let mut state = init::init(&point, &context, &config);
    let init_s = mark.elapsed().as_secs_f64();

    let facts: String = envelope::describe(&context)
        .iter()
        .map(|(key, value)| format!(",\"{key}\":\"{}\"", clean(value)))
        .collect();
    let head = format!(
        "\"point\":{{\"N\":{},\"log_delta\":{},\"output_k\":{},\"key_seed\":{}}},\"warmup\":{},\"config\":{}{facts}",
        point.N, point.log_delta, point.output_k, point.key_seed, envelope::WARMUP,
        config_json(&config),
    );
    let mut rows: Vec<String> = Vec::new();
    let mut warmup_s = 0.0f64;
    report(&out_root, &head, setup_s, init_s, warmup_s, &rows);

    let mut warmed = false;
    for i in 0..total {
        let case_dir = root.join("cases").join(format!("{i:06}"));
        let answer_dir = out_root.join(format!("{i:06}"));

        let inputs = match inputs_of(&case_dir, &point) {
            Ok(inputs) => inputs,
            Err(failure) => {
                rows.push(crashed_row(i, &format!("reading the case: {failure}")));
                report(&out_root, &head, setup_s, init_s, warmup_s, &rows);
                continue;
            }
        };

        // GENERATE: the case from its inputs, by the envelope. Timed apart.
        let mark = Instant::now();
        let input = envelope::generate(&context, &inputs);
        let generate_s = mark.elapsed().as_secs_f64();

        // WARM-UP: discarded runs before the first timed one. Timed as a whole.
        if !warmed {
            let mark = Instant::now();
            for _ in 0..envelope::WARMUP {
                run::run(&mut state, &input);
            }
            warmup_s = mark.elapsed().as_secs_f64();
            warmed = true;
        }

        // RUN: monotonic, and around the call and nothing else. The score.
        let started = Instant::now();
        let output = run::run(&mut state, &input);
        let seconds = started.elapsed().as_secs_f64();

        // SERIALIZE: the output as the envelope's canonical bytes, and the digest.
        let mark = Instant::now();
        let mut files = envelope::serialize(output);
        files.sort_by(|a, b| a.0.cmp(b.0));
        let sha = digest_of(&files);
        let digest_s = mark.elapsed().as_secs_f64();
        if let Some(wrong) = misnamed(&files) {
            rows.push(crashed_row(i, &wrong));
            report(&out_root, &head, setup_s, init_s, warmup_s, &rows);
            continue;
        }

        // WRITE: the bytes to out/, for the platform to hash the same way.
        let mark = Instant::now();
        let written = fs::create_dir_all(&answer_dir).and_then(|_| {
            files
                .iter()
                .try_for_each(|(name, bytes)| fs::write(answer_dir.join(format!("{name}.bin")), bytes))
        });
        if let Err(failure) = written {
            rows.push(crashed_row(i, &format!("writing the answer: {failure}")));
            report(&out_root, &head, setup_s, init_s, warmup_s, &rows);
            continue;
        }
        let write_s = mark.elapsed().as_secs_f64();

        // CHECK: the envelope's reading of the output. Metrics, not the score.
        let mark = Instant::now();
        let check = envelope::check(&context, &input, output);
        let check_s = mark.elapsed().as_secs_f64();

        let metrics: Vec<String> = check
            .metrics
            .iter()
            .map(|(key, value)| format!("\"{key}\":{}", json_number(*value)))
            .collect();
        let note = check
            .note
            .as_deref()
            .map(|text| format!(",\"note\":\"{}\"", clean(text)))
            .unwrap_or_default();
        rows.push(format!(
            concat!(
                "{{\"i\":{i},\"seconds\":{seconds:.9},\"status\":\"ok\",\"valid\":{valid},",
                "\"generate_s\":{generate_s:.9},\"digest_s\":{digest_s:.9},\"write_s\":{write_s:.9},\"check_s\":{check_s:.9},",
                "\"digest\":\"{sha}\",\"metrics\":{{{metrics}}}{note}}}"
            ),
            i = i,
            seconds = seconds,
            valid = check.valid,
            generate_s = generate_s,
            digest_s = digest_s,
            write_s = write_s,
            check_s = check_s,
            sha = sha,
            metrics = metrics.join(","),
            note = note,
        ));
        report(&out_root, &head, setup_s, init_s, warmup_s, &rows);
    }

    free::free(state);
    Ok(())
}

/// Written after every case, not at the end: a process killed on its timeout
/// has still done the cases before it.
fn report(out: &Path, head: &str, setup_s: f64, init_s: f64, warmup_s: f64, rows: &[String]) {
    let body = format!(
        "{{{head},\"setup_s\":{setup_s:.9},\"init_s\":{init_s:.9},\"warmup_s\":{warmup_s:.9},\"max_rss_bytes\":{},\"cases\":[{}]}}",
        max_rss_bytes(),
        rows.join(",")
    );
    let _ = fs::write(out.join("results.json"), body);
}

fn crashed_row(i: usize, why: &str) -> String {
    format!("{{\"i\":{i},\"seconds\":null,\"status\":\"crashed\",\"note\":\"{}\"}}", clean(why))
}

/// Text safe inside a JSON string: quotes, backslashes and newlines become
/// spaces, and it is cut short. A note is for reading, not for parsing back.
fn clean(text: &str) -> String {
    text.chars()
        .take(200)
        .map(|c| if c == '"' || c == '\\' || c == '\n' || c == '\r' { ' ' } else { c })
        .collect()
}

fn json_number(value: f64) -> String {
    if value.is_finite() {
        format!("{value:.6}")
    } else {
        "null".to_string()
    }
}

/// The config as a JSON object in the report — comments stripped — so the
/// parameters a run was made with travel with its numbers. Not valid JSON
/// after stripping, and the report says so with `null`.
fn config_json(text: &str) -> String {
    let stripped: String = text
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    let trimmed = stripped.trim();
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        trimmed.split_whitespace().collect::<Vec<_>>().join(" ")
    } else {
        "null".to_string()
    }
}

/// The digest of what a case wrote, the platform's recipe: one file, its
/// sha256; several, sha256 over each file's name, a zero byte and its bytes,
/// in name order. `files` must already be in name order.
fn digest_of(files: &[(&str, Vec<u8>)]) -> String {
    let mut hasher = Sha256::new();
    if files.len() == 1 {
        hasher.update(&files[0].1);
    } else {
        for (name, bytes) in files {
            hasher.update(format!("{name}.bin").as_bytes());
            hasher.update([0u8]);
            hasher.update(bytes);
        }
    }
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// `serialize` must answer with the signature's results and no others.
fn misnamed(files: &[(&str, Vec<u8>)]) -> Option<String> {
    let mut expected: Vec<&str> = RESULTS.to_vec();
    expected.sort_unstable();
    let got: Vec<&str> = files.iter().map(|(name, _)| *name).collect();
    if got == expected {
        None
    } else {
        Some(format!("serialize returned {got:?}; the signature declares {expected:?}"))
    }
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
/// argument, little-endian, no header; a tensor's shape follows from the point.
fn inputs_of(dir: &Path, point: &Point) -> Anyhow<Inputs> {
    let _ = point;
    Ok(Inputs {
        case_seed: read_scalar::<u64>(dir, "case_seed")?,
    })
}

/// Little-endian on the wire, and on every platform this runs on.
trait Wire: Sized + Copy {
    fn from_wire(bytes: &[u8]) -> Self;
}

macro_rules! wire {
    ($($t:ty),*) => {$(
        impl Wire for $t {
            fn from_wire(bytes: &[u8]) -> Self {
                Self::from_le_bytes(bytes.try_into().expect("width"))
            }
        }
    )*};
}
wire!(i8, i16, i32, i64, u8, u16, u32, u64, f32, f64);

#[allow(dead_code)]
fn read_scalar<T: Wire>(dir: &Path, name: &str) -> Anyhow<T> {
    let raw = fs::read(dir.join(format!("{name}.bin")))?;
    let width = std::mem::size_of::<T>();
    if raw.len() != width {
        return Err(format!("{name}: {} bytes for one value of {width}", raw.len()).into());
    }
    Ok(T::from_wire(&raw))
}

#[allow(dead_code)]
fn read_tensor<T: Wire>(dir: &Path, name: &str, dims: &[usize]) -> Anyhow<Tensor<T>> {
    let raw = fs::read(dir.join(format!("{name}.bin")))?;
    let width = std::mem::size_of::<T>();
    let count: usize = dims.iter().product();
    if raw.len() != count * width {
        return Err(format!("{name}: {} bytes for {count} values", raw.len()).into());
    }
    Ok(Tensor {
        shape: dims.iter().map(|d| *d as i64).collect(),
        data: raw.chunks_exact(width).map(T::from_wire).collect(),
    })
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

/// A point directory, the way the bundle's `make` writes one, for a signature
/// whose arguments are seeds: the manifest carries the point's parameters and
/// the case count; case i holds seeds[i] in every argument.
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
    let (Some(dir), Some(point_text), Some(seeds)) = (dir, point, seeds) else {
        return Err("make <dir> --point '{...}' --seeds 1,2,3".into());
    };
    let point = point_of(&point_text)?;
    let seeds: Vec<u64> = seeds.split(',').map(|s| s.trim().parse()).collect::<Result<_, _>>()?;

    let root = Path::new(&dir);
    for (i, &seed) in seeds.iter().enumerate() {
        let case_dir = root.join("cases").join(format!("{i:06}"));
        fs::create_dir_all(&case_dir)?;
        fs::write(case_dir.join("case_seed.bin"), (seed as u64).to_le_bytes())?;
    }
    fs::write(
        root.join("manifest.json"),
        format!("{{\"N\":{},\"log_delta\":{},\"output_k\":{},\"key_seed\":{},\"cases\":{}}}\n", point.N, point.log_delta, point.output_k, point.key_seed, seeds.len()),
    )?;
    println!("{}: {point:?} cases={} seeds={seeds:?}", root.display(), seeds.len());
    Ok(())
}
