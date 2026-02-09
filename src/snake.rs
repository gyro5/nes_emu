use rand::Rng;
use sdl3::{
    self, EventPump,
    event::Event,
    keyboard::Keycode,
    pixels::{Color, PixelFormat},
    render,
};

use crate::cpu::CPU;
use crate::mem::Mem;

/*
Memory mapping for the game:
- 0xFE: Place to input RNG byte
- 0xFF: Place to put user's input
- 0x200 -> 0x600: 32x32 bytes for the graphic output (the CPU will write there)
- 0x600...: The gamecode
*/

pub fn run() {
    // Set up SDL3 (following the example in the docs)
    let sld_context = sdl3::init().unwrap();

    // Get the video subsystem to use graphic functionality
    let video_subsystem = sld_context.video().unwrap();

    // Get an eventpump
    let mut event_pump = sld_context.event_pump().unwrap();

    // Create a window
    let window = video_subsystem
        .window("Snake Game", 640, 640)
        .build()
        .unwrap();

    // Create a canvas to be able to draw on the window
    let mut canvas = window.into_canvas();
    canvas.set_scale(20.0, 20.0).unwrap();

    let creator = canvas.texture_creator();
    let mut texture = creator
        .create_texture_target(PixelFormat::RGB24, 32, 32)
        .unwrap();

    // To fix the texture being blurry
    texture.set_scale_mode(render::ScaleMode::Nearest);

    // This is used as a buffer for the texture
    let mut screen_state = [0 as u8; 32 * 3 * 32];

    let mut rng = rand::rng();

    // Snake game code
    let game_code = vec![
        0x20, 0x06, 0x06, 0x20, 0x38, 0x06, 0x20, 0x0d, 0x06, 0x20, 0x2a, 0x06, 0x60, 0xa9, 0x02,
        0x85, 0x02, 0xa9, 0x04, 0x85, 0x03, 0xa9, 0x11, 0x85, 0x10, 0xa9, 0x10, 0x85, 0x12, 0xa9,
        0x0f, 0x85, 0x14, 0xa9, 0x04, 0x85, 0x11, 0x85, 0x13, 0x85, 0x15, 0x60, 0xa5, 0xfe, 0x85,
        0x00, 0xa5, 0xfe, 0x29, 0x03, 0x18, 0x69, 0x02, 0x85, 0x01, 0x60, 0x20, 0x4d, 0x06, 0x20,
        0x8d, 0x06, 0x20, 0xc3, 0x06, 0x20, 0x19, 0x07, 0x20, 0x20, 0x07, 0x20, 0x2d, 0x07, 0x4c,
        0x38, 0x06, 0xa5, 0xff, 0xc9, 0x77, 0xf0, 0x0d, 0xc9, 0x64, 0xf0, 0x14, 0xc9, 0x73, 0xf0,
        0x1b, 0xc9, 0x61, 0xf0, 0x22, 0x60, 0xa9, 0x04, 0x24, 0x02, 0xd0, 0x26, 0xa9, 0x01, 0x85,
        0x02, 0x60, 0xa9, 0x08, 0x24, 0x02, 0xd0, 0x1b, 0xa9, 0x02, 0x85, 0x02, 0x60, 0xa9, 0x01,
        0x24, 0x02, 0xd0, 0x10, 0xa9, 0x04, 0x85, 0x02, 0x60, 0xa9, 0x02, 0x24, 0x02, 0xd0, 0x05,
        0xa9, 0x08, 0x85, 0x02, 0x60, 0x60, 0x20, 0x94, 0x06, 0x20, 0xa8, 0x06, 0x60, 0xa5, 0x00,
        0xc5, 0x10, 0xd0, 0x0d, 0xa5, 0x01, 0xc5, 0x11, 0xd0, 0x07, 0xe6, 0x03, 0xe6, 0x03, 0x20,
        0x2a, 0x06, 0x60, 0xa2, 0x02, 0xb5, 0x10, 0xc5, 0x10, 0xd0, 0x06, 0xb5, 0x11, 0xc5, 0x11,
        0xf0, 0x09, 0xe8, 0xe8, 0xe4, 0x03, 0xf0, 0x06, 0x4c, 0xaa, 0x06, 0x4c, 0x35, 0x07, 0x60,
        0xa6, 0x03, 0xca, 0x8a, 0xb5, 0x10, 0x95, 0x12, 0xca, 0x10, 0xf9, 0xa5, 0x02, 0x4a, 0xb0,
        0x09, 0x4a, 0xb0, 0x19, 0x4a, 0xb0, 0x1f, 0x4a, 0xb0, 0x2f, 0xa5, 0x10, 0x38, 0xe9, 0x20,
        0x85, 0x10, 0x90, 0x01, 0x60, 0xc6, 0x11, 0xa9, 0x01, 0xc5, 0x11, 0xf0, 0x28, 0x60, 0xe6,
        0x10, 0xa9, 0x1f, 0x24, 0x10, 0xf0, 0x1f, 0x60, 0xa5, 0x10, 0x18, 0x69, 0x20, 0x85, 0x10,
        0xb0, 0x01, 0x60, 0xe6, 0x11, 0xa9, 0x06, 0xc5, 0x11, 0xf0, 0x0c, 0x60, 0xc6, 0x10, 0xa5,
        0x10, 0x29, 0x1f, 0xc9, 0x1f, 0xf0, 0x01, 0x60, 0x4c, 0x35, 0x07, 0xa0, 0x00, 0xa5, 0xfe,
        0x91, 0x00, 0x60, 0xa6, 0x03, 0xa9, 0x00, 0x81, 0x10, 0xa2, 0x00, 0xa9, 0x01, 0x81, 0x10,
        0x60, 0xa6, 0xff, 0xea, 0xea, 0xca, 0xd0, 0xfb, 0x60,
    ];

    //load the game
    let mut cpu = CPU::new();
    cpu.load(game_code);
    cpu.reset();

    // run the game cycle
    cpu.run_with_callback(move |cpu| {
        // Handle user input. In particular, pressing WASD will write to a specific
        // byte in the CPU's memory that is used for user input.
        handle_user_input(cpu, &mut event_pump);

        // Random byte for the position of the food
        cpu.mem_write(0xfe, rng.random_range(1..16));

        // read_screen_state() will read the game graphic from the CPU's memory
        // and output the corresponding pixel values into the buffer. This function
        // will return true if the buffer actually changes (to avoid unnecessary redraw).
        //
        // This check is needed because the CPU will call this callback after
        // every instruction (which mostly don't change the screen).
        if read_screen_state(cpu, &mut screen_state) {
            // Update the texture with the buffer
            texture.update(None, &screen_state, 32 * 3).unwrap();

            // Copy the texture to the display target (ie. the canvas)
            canvas.copy(&texture, None, None).unwrap();

            // Draw the canvas content on the window
            canvas.present();
        }

        std::thread::sleep(std::time::Duration::new(0, 70_000));
    });
}

fn read_screen_state(cpu: &CPU, frame: &mut [u8; 32 * 3 * 32]) -> bool {
    let mut frame_idx = 0;
    let mut update = false;
    for i in 0x0200..0x600 {
        // Read the byte from the CPU's memory
        let color_byte = cpu.mem_read(i as u16);

        // Get the corresponding color
        let (b1, b2, b3) = color(color_byte).rgb();

        // Only update the buffer if the pixel actually change
        if frame[frame_idx] != b1 || frame[frame_idx + 1] != b2 || frame[frame_idx + 2] != b3 {
            frame[frame_idx] = b1;
            frame[frame_idx + 1] = b2;
            frame[frame_idx + 2] = b3;
            update = true;
        }
        frame_idx += 3;
    }
    update
}

/// Return a SDL3 pixel color based from a byte value
fn color(byte: u8) -> Color {
    match byte {
        0 => sdl3::pixels::Color::BLACK,
        1 => sdl3::pixels::Color::WHITE,
        2 | 9 => sdl3::pixels::Color::GREY,
        3 | 10 => sdl3::pixels::Color::RED,
        4 | 11 => sdl3::pixels::Color::GREEN,
        5 | 12 => sdl3::pixels::Color::BLUE,
        6 | 13 => sdl3::pixels::Color::MAGENTA,
        7 | 14 => sdl3::pixels::Color::YELLOW,
        _ => sdl3::pixels::Color::CYAN,
    }
}

/// Handle user input for a SDL3's EventPump
fn handle_user_input(cpu: &mut CPU, event_pump: &mut EventPump) {
    for event in event_pump.poll_iter() {
        match event {
            Event::Quit { .. }
            | Event::KeyDown {
                keycode: Some(Keycode::Escape),
                ..
            } => std::process::exit(0),

            Event::KeyDown {
                keycode: Some(Keycode::W),
                ..
            } => {
                cpu.mem_write(0xff, 0x77);
            }

            Event::KeyDown {
                keycode: Some(Keycode::S),
                ..
            } => {
                cpu.mem_write(0xff, 0x73);
            }

            Event::KeyDown {
                keycode: Some(Keycode::A),
                ..
            } => {
                cpu.mem_write(0xff, 0x61);
            }

            Event::KeyDown {
                keycode: Some(Keycode::D),
                ..
            } => {
                cpu.mem_write(0xff, 0x64);
            }

            _ => { /* do nothing */ }
        }
    }
}
