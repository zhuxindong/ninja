// src/main.rs
use viuer::{print_from_file, Config};

fn main() {
    let conf = Config {
        // set offset
        x: 0,
        y: 0,
        use_iterm: true,
        ..Default::default()
    };

    // starting from row 4 and column 20,
    // display `img.jpg` with dimensions 80x25 (in terminal cells)
    // note that the actual resolution in the terminal will be 80x50
    print_from_file(
        "/Users/gngpp/GolandProjects/funcaptcha/image_1693180034986.png",
        &conf,
    )
    .expect("Image printing failed.");
}
