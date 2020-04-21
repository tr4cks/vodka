use std::fs::{create_dir_all, File};
use std::include_bytes;
use std::io::copy;
use std::path::Path;

use zip;

const ASSET_PYTHON_ZIP: &'static [u8] =
    include_bytes!(r"asset\python-3.8.2-embed-amd64-packaged.zip");

// TODO: Replace all unwrap() to replace it with Result.
//       This function may return zip::ZipError or std::error::Error errors.
//       Generic error without an enum?
pub fn unzip_python_library(path: &Path) {
    if !path.exists() {
        // TODO: return error if path does not exists.
    }

    // TODO: why that doesn't work without specifying the type?
    //       let asset_python_zip = include_bytes!(r"asset\python-3.8.2-embed-amd64-packaged.zip");

    let reader = std::io::Cursor::new(ASSET_PYTHON_ZIP);
    let mut zip = zip::ZipArchive::new(reader).unwrap();
    for i in 0..zip.len() {
        let mut file = zip.by_index(i).unwrap();
        // TODO: passing as reference or not? don't understand very well...
        //       This function take a path who must be a subtype of AsRef<Path>
        let out_path = path.join(&file.sanitized_name());
        // TODO: why &*
        if (&*file.name()).ends_with('/') {
            create_dir_all(&out_path).unwrap();
        } else {
            if let Some(p) = out_path.parent() {
                if !p.exists() {
                    create_dir_all(&p).unwrap();
                }
            }
            let mut out_file = File::create(&out_path).unwrap();
            copy(&mut file, &mut out_file).unwrap();
        }
    }
}
