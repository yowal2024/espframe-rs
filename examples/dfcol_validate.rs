use espframe::physics::dfcol::{DfcolArchive, DfcolZipModels, Scene};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: dfcol_validate <dfcol.zip>")?;
    let bytes = std::fs::read(path)?;
    let archive = DfcolArchive::Open(&bytes)?;
    println!("Opened archive: {} bytes", archive.StoredSize());
    for model in DfcolZipModels() {
        let raw = archive.Inflate(model.entry_name)?;
        let scene = Scene::Load(&raw, model.map_name)
            .map_err(|error| format!("{}: {error}", model.map_name))?;
        println!(
            "{}: {} bytes, {} actors, {} source triangles",
            model.map_name,
            raw.len(),
            scene.Stats().actors,
            scene.Stats().source_triangles,
        );
    }
    Ok(())
}
