use std::fs::{create_dir_all, File};
use std::include_bytes;
use std::io::copy;
use std::path::Path;
use std::path::PathBuf;

const ASSET_PYTHON_ZIP: &[u8] = include_bytes!(r"asset\python-3.8.2-embed-amd64-packaged.zip");

pub struct PythonBundle {
    pub root: PathBuf,
    pub interpreter: PathBuf,
    pub library: PathBuf,
}

pub fn unzip_python_library<P: AsRef<Path>>(path: P) -> anyhow::Result<PythonBundle> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(anyhow::anyhow!("Path does not exist"));
    }
    let reader = std::io::Cursor::new(ASSET_PYTHON_ZIP);
    let mut zip = zip::ZipArchive::new(reader)?;
    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        let out_path = path.join(file.sanitized_name());
        if file.name().ends_with('/') {
            create_dir_all(out_path)?;
        } else {
            if let Some(p) = out_path.parent() {
                if !p.exists() {
                    create_dir_all(p)?;
                }
            }
            let mut out_file = File::create(out_path)?;
            copy(&mut file, &mut out_file)?;
        }
    }
    Ok(PythonBundle {
        root: PathBuf::from(path),
        interpreter: path.join("python.exe"),
        library: path.join("python38.dll"),
    })
}
