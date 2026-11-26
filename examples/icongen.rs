//! Icon generator for Predator Remote Controller: `cargo run --example icongen [-- <output-dir>]`.
//!
//! Renders the ORIGINAL product logo with a small built-in vector rasterizer (signed-distance
//! shapes, 8x8 supersampling per pixel, premultiplied compositing) and writes:
//!
//! * `assets/predator.ico` — normal icon, frames 16, 20, 24, 32, 40, 48, 64, 128, 256 px
//! * `assets/predator-off.ico` — "service stopped" variant (grey badge + red status dot), 16–48 px
//! * `assets/predator-256.png`, `assets/predator-off-48.png` — previews for the README
//! * `assets/preview-sizes.png` — contact sheet of the 16/24/32 px frames at 8x zoom on dark and
//!   light backgrounds (plus 1:1 strips), used to check legibility of the small sizes
//!
//! Artwork: a dark navy rounded-square badge carrying a bold geometric "P" in neon red-orange whose
//! round bowl "transmits" cyan signal arcs (remote control). It is drawn from code only — no
//! external art, fonts or third-party logos. The 16–32 px frames use hand-hinted geometry snapped
//! to the pixel grid (thicker strokes, a single arc at ≤ 24 px) so they stay crisp in the
//! notification area.
//!
//! Every frame is a 32-bit RGBA PNG. The PNG container (chunks, CRC-32, row filters) and the zlib
//! wrapper (header + Adler-32) are written here; only the DEFLATE step uses `miniz_oxide` (a
//! dev-dependency, never linked into the release binaries).
//!
//! The `.res` writer in `build.rs` is compiled into this example's test target too, so the
//! generated icons are verified against the code that embeds them (`cargo test --example icongen`).

use std::error::Error;
use std::f32::consts::PI;
use std::fs;
use std::ops::{Add, Mul, Sub};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

type AppResult<T> = Result<T, Box<dyn Error>>;

/// Frames of `predator.ico` (Explorer, taskbar, Alt+Tab, tray at 100–250 % scaling).
const NORMAL_SIZES: [u32; 9] = [16, 20, 24, 32, 40, 48, 64, 128, 256];
/// Frames of `predator-off.ico` (tray only).
const OFF_SIZES: [u32; 6] = [16, 20, 24, 32, 40, 48];
/// Supersampling grid per pixel axis (8x8 = 64 coverage samples per pixel).
const SUPERSAMPLE: u32 = 8;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("icongen: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> AppResult<()> {
    let out_dir = match std::env::args_os().nth(1) {
        Some(dir) => PathBuf::from(dir),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("assets"),
    };
    fs::create_dir_all(&out_dir).map_err(|e| format!("cannot create {}: {e}", out_dir.display()))?;

    let normal: Vec<Image> = NORMAL_SIZES.iter().map(|&s| render(s, &logo_layers(s, Variant::Normal))).collect();
    let off: Vec<Image> = OFF_SIZES.iter().map(|&s| render(s, &logo_layers(s, Variant::Stopped))).collect();

    write(&out_dir.join("predator.ico"), &encode_ico(&normal)?)?;
    write(&out_dir.join("predator-off.ico"), &encode_ico(&off)?)?;
    write(&out_dir.join("predator-256.png"), &encode_png(find(&normal, 256)?))?;
    write(&out_dir.join("predator-off-48.png"), &encode_png(find(&off, 48)?))?;
    write(&out_dir.join("preview-sizes.png"), &encode_png(&contact_sheet(&normal, &off)?))?;
    Ok(())
}

fn write(path: &Path, bytes: &[u8]) -> AppResult<()> {
    fs::write(path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    println!("wrote {} ({} bytes)", path.display(), bytes.len());
    Ok(())
}

fn find(images: &[Image], size: u32) -> AppResult<&Image> {
    images.iter().find(|i| i.width == size).ok_or_else(|| format!("no {size} px frame rendered").into())
}

// ---------------------------------------------------------------------------------------------
// Geometry: signed distance functions (negative inside), pixel space, y grows downwards.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
struct P2 {
    x: f32,
    y: f32,
}

const fn p2(x: f32, y: f32) -> P2 {
    P2 { x, y }
}

impl P2 {
    fn dot(self, o: P2) -> f32 {
        self.x * o.x + self.y * o.y
    }

    fn len(self) -> f32 {
        self.dot(self).sqrt()
    }
}

impl Add for P2 {
    type Output = P2;
    fn add(self, o: P2) -> P2 {
        p2(self.x + o.x, self.y + o.y)
    }
}

impl Sub for P2 {
    type Output = P2;
    fn sub(self, o: P2) -> P2 {
        p2(self.x - o.x, self.y - o.y)
    }
}

impl Mul<f32> for P2 {
    type Output = P2;
    fn mul(self, k: f32) -> P2 {
        p2(self.x * k, self.y * k)
    }
}

#[derive(Clone, Debug)]
enum Shape {
    /// Axis-aligned rectangle with rounded corners (`r = 0` for a sharp rectangle).
    RoundRect {
        x0: f32,
        y0: f32,
        x1: f32,
        y1: f32,
        r: f32,
    },
    Circle {
        c: P2,
        r: f32,
    },
    /// Ring segment with round caps: centre-line radius `r`, half thickness `hw`, sweeping from
    /// angle `a0` to `a1` (radians; 0 = +x, positive = clockwise on screen because y is down).
    Arc {
        c: P2,
        r: f32,
        hw: f32,
        a0: f32,
        a1: f32,
    },
    Union(Vec<Shape>),
    Subtract(Box<Shape>, Box<Shape>),
    /// Grows (`d > 0`) or shrinks (`d < 0`) a shape.
    Offset(Box<Shape>, f32),
}

impl Shape {
    fn rect(x0: f32, y0: f32, x1: f32, y1: f32) -> Shape {
        Shape::RoundRect { x0, y0, x1, y1, r: 0.0 }
    }

    fn circle(c: P2, r: f32) -> Shape {
        Shape::Circle { c, r }
    }

    fn subtract(a: Shape, b: Shape) -> Shape {
        Shape::Subtract(Box::new(a), Box::new(b))
    }

    fn offset(a: Shape, d: f32) -> Shape {
        Shape::Offset(Box::new(a), d)
    }

    /// Signed distance from `p` to the shape outline (exact for primitives, a bound for CSG).
    fn sd(&self, p: P2) -> f32 {
        match self {
            Shape::RoundRect { x0, y0, x1, y1, r } => {
                let hx = (x1 - x0) * 0.5;
                let hy = (y1 - y0) * 0.5;
                let r = r.min(hx).min(hy).max(0.0);
                let qx = (p.x - (x0 + x1) * 0.5).abs() - hx + r;
                let qy = (p.y - (y0 + y1) * 0.5).abs() - hy + r;
                p2(qx.max(0.0), qy.max(0.0)).len() + qx.max(qy).min(0.0) - r
            }
            Shape::Circle { c, r } => (p - *c).len() - r,
            Shape::Arc { c, r, hw, a0, a1 } => {
                let d = p - *c;
                let mid = (a0 + a1) * 0.5;
                let half = (a1 - a0).abs() * 0.5;
                if wrap_angle(d.y.atan2(d.x) - mid).abs() <= half {
                    (d.len() - r).abs() - hw
                } else {
                    let cap = |a: f32| (d - p2(a.cos(), a.sin()) * *r).len();
                    cap(*a0).min(cap(*a1)) - hw
                }
            }
            Shape::Union(shapes) => shapes.iter().map(|s| s.sd(p)).fold(f32::INFINITY, f32::min),
            Shape::Subtract(a, b) => a.sd(p).max(-b.sd(p)),
            Shape::Offset(a, d) => a.sd(p) - d,
        }
    }
}

/// Wraps an angle into (-PI, PI].
fn wrap_angle(a: f32) -> f32 {
    let mut a = a % (2.0 * PI);
    if a > PI {
        a -= 2.0 * PI;
    } else if a <= -PI {
        a += 2.0 * PI;
    }
    a
}

// ---------------------------------------------------------------------------------------------
// Paint and compositing.
// ---------------------------------------------------------------------------------------------

/// Straight-alpha sRGB colour, components in 0..=1.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Rgba {
    r: f32,
    g: f32,
    b: f32,
    a: f32,
}

const fn rgba(hex: u32, a: f32) -> Rgba {
    Rgba {
        r: ((hex >> 16) & 0xFF) as f32 / 255.0,
        g: ((hex >> 8) & 0xFF) as f32 / 255.0,
        b: (hex & 0xFF) as f32 / 255.0,
        a,
    }
}

const fn rgb(hex: u32) -> Rgba {
    rgba(hex, 1.0)
}

impl Rgba {
    fn lerp(self, o: Rgba, t: f32) -> Rgba {
        let m = |a: f32, b: f32| a + (b - a) * t;
        Rgba { r: m(self.r, o.r), g: m(self.g, o.g), b: m(self.b, o.b), a: m(self.a, o.a) }
    }

    fn with_alpha(self, a: f32) -> Rgba {
        Rgba { a, ..self }
    }
}

#[derive(Clone, Copy, Debug)]
enum Paint {
    Solid(Rgba),
    Linear { from: P2, to: P2, c0: Rgba, c1: Rgba },
    Radial { center: P2, radius: f32, c0: Rgba, c1: Rgba },
}

impl Paint {
    fn vertical(y0: f32, y1: f32, c0: Rgba, c1: Rgba) -> Paint {
        Paint::Linear { from: p2(0.0, y0), to: p2(0.0, y1), c0, c1 }
    }

    fn at(&self, p: P2) -> Rgba {
        match *self {
            Paint::Solid(c) => c,
            Paint::Linear { from, to, c0, c1 } => {
                let d = to - from;
                let len2 = d.dot(d);
                let t = if len2 > 0.0 { ((p - from).dot(d) / len2).clamp(0.0, 1.0) } else { 0.0 };
                c0.lerp(c1, t)
            }
            Paint::Radial { center, radius, c0, c1 } => {
                let t = if radius > 0.0 { ((p - center).len() / radius).clamp(0.0, 1.0) } else { 1.0 };
                c0.lerp(c1, t)
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Coverage {
    /// Hard-edged fill; anti-aliasing comes from supersampling.
    Fill,
    /// Soft halo around the shape that fades out over `radius` pixels.
    Glow { radius: f32 },
}

#[derive(Clone, Debug)]
struct Layer {
    shape: Shape,
    paint: Paint,
    coverage: Coverage,
    /// Optional clip region; nothing of the layer is drawn outside it.
    clip: Option<Shape>,
}

impl Layer {
    fn fill(shape: Shape, paint: Paint) -> Layer {
        Layer { shape, paint, coverage: Coverage::Fill, clip: None }
    }

    fn glow(shape: Shape, color: Rgba, radius: f32, clip: Shape) -> Layer {
        Layer { shape, paint: Paint::Solid(color), coverage: Coverage::Glow { radius }, clip: Some(clip) }
    }

    fn alpha_at(&self, p: P2) -> f32 {
        if self.clip.as_ref().is_some_and(|clip| clip.sd(p) >= 0.0) {
            return 0.0;
        }
        let d = self.shape.sd(p);
        match self.coverage {
            Coverage::Fill => {
                if d < 0.0 {
                    1.0
                } else {
                    0.0
                }
            }
            Coverage::Glow { radius } => {
                if d <= 0.0 {
                    1.0
                } else if d >= radius {
                    0.0
                } else {
                    let t = 1.0 - d / radius;
                    t * t
                }
            }
        }
    }
}

/// Composites all layers at one sample point; returns premultiplied RGBA.
fn composite(layers: &[Layer], p: P2) -> [f32; 4] {
    let mut out = [0.0f32; 4];
    for layer in layers {
        let coverage = layer.alpha_at(p);
        if coverage <= 0.0 {
            continue;
        }
        let c = layer.paint.at(p);
        let a = coverage * c.a;
        let k = 1.0 - a;
        out = [c.r * a + out[0] * k, c.g * a + out[1] * k, c.b * a + out[2] * k, a + out[3] * k];
    }
    out
}

/// Straight-alpha RGBA8 image, rows top to bottom.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Image {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

impl Image {
    fn new(width: u32, height: u32) -> Image {
        Image { width, height, rgba: vec![0; width as usize * height as usize * 4] }
    }

    fn index(&self, x: u32, y: u32) -> usize {
        (y as usize * self.width as usize + x as usize) * 4
    }

    fn pixel(&self, x: u32, y: u32) -> [u8; 4] {
        let i = self.index(x, y);
        [self.rgba[i], self.rgba[i + 1], self.rgba[i + 2], self.rgba[i + 3]]
    }

    fn set_pixel(&mut self, x: u32, y: u32, px: [u8; 4]) {
        let i = self.index(x, y);
        self.rgba[i..i + 4].copy_from_slice(&px);
    }

    fn fill(&mut self, px: [u8; 4]) {
        for (i, b) in self.rgba.iter_mut().enumerate() {
            *b = px[i % 4];
        }
    }

    /// Draws `src` scaled by an integer `zoom` (nearest neighbour) at (`x0`, `y0`), alpha-blended
    /// over the existing (opaque) pixels.
    fn blit(&mut self, src: &Image, x0: u32, y0: u32, zoom: u32) {
        for y in 0..src.height * zoom {
            for x in 0..src.width * zoom {
                let (dx, dy) = (x0 + x, y0 + y);
                if dx >= self.width || dy >= self.height {
                    continue;
                }
                let s = src.pixel(x / zoom, y / zoom);
                let d = self.pixel(dx, dy);
                let a = u32::from(s[3]);
                let mix = |s: u8, d: u8| ((u32::from(s) * a + u32::from(d) * (255 - a) + 127) / 255) as u8;
                self.set_pixel(dx, dy, [mix(s[0], d[0]), mix(s[1], d[1]), mix(s[2], d[2]), 255]);
            }
        }
    }
}

/// Converts an averaged premultiplied sample to straight RGBA8.
fn to_rgba8(premul: [f32; 4]) -> [u8; 4] {
    let a = premul[3].clamp(0.0, 1.0);
    if a < 0.5 / 255.0 {
        return [0, 0, 0, 0];
    }
    let q = |v: f32| (v.clamp(0.0, 1.0) * 255.0).round() as u8;
    [q(premul[0] / a), q(premul[1] / a), q(premul[2] / a), q(a)]
}

/// Rasterizes `layers` into a `size` x `size` image with `SUPERSAMPLE`² samples per pixel.
fn render(size: u32, layers: &[Layer]) -> Image {
    let mut img = Image::new(size, size);
    let n = SUPERSAMPLE;
    let step = 1.0 / n as f32;
    let norm = 1.0 / (n * n) as f32;
    for y in 0..size {
        for x in 0..size {
            let mut acc = [0.0f32; 4];
            for sy in 0..n {
                for sx in 0..n {
                    let p = p2(x as f32 + (sx as f32 + 0.5) * step, y as f32 + (sy as f32 + 0.5) * step);
                    for (a, v) in acc.iter_mut().zip(composite(layers, p)) {
                        *a += v;
                    }
                }
            }
            img.set_pixel(x, y, to_rgba8(acc.map(|v| v * norm)));
        }
    }
    img
}

// ---------------------------------------------------------------------------------------------
// The logo.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant {
    /// Service running: navy badge, red-orange "P", cyan signal arcs.
    Normal,
    /// Service stopped: grey badge and "P", no signal, red status dot.
    Stopped,
}

/// Logo geometry for one frame size, in pixels.
#[derive(Clone, Debug, PartialEq)]
struct Geom {
    size: f32,
    /// Badge inset from the frame edge.
    margin: f32,
    /// Badge corner radius.
    radius: f32,
    /// Width of the badge's inner highlight border.
    border: f32,
    /// Left / right edge of the stem of the "P".
    stem_x0: f32,
    stem_x1: f32,
    /// Top of the "P" (stem and bowl) and bottom of the stem.
    top: f32,
    bottom: f32,
    /// Bottom edge of the bowl.
    bowl_bottom: f32,
    /// Centre x of the bowl's half circle.
    bowl_cx: f32,
    /// Stroke thickness of the bowl.
    bowl_t: f32,
    /// Signal arcs around the bowl centre: (centre-line radius, half thickness).
    arcs: Vec<(f32, f32)>,
    /// Half of the angular sweep of the signal arcs, in degrees.
    sweep_deg: f32,
    /// Neon glow radius (0 = none; small frames stay flat for crispness).
    glow: f32,
}

/// Master design on a 256 px grid; other sizes are scaled from it (and snapped to whole pixels up
/// to 48 px) unless they have a hand-hinted entry in [`Geom::for_size`].
const MASTER: Geom = Geom {
    size: 256.0,
    margin: 8.0,
    radius: 54.0,
    border: 3.0,
    stem_x0: 34.0,
    stem_x1: 74.0,
    top: 50.0,
    bottom: 206.0,
    bowl_bottom: 160.0,
    bowl_cx: 106.0,
    bowl_t: 38.0,
    arcs: Vec::new(),
    sweep_deg: 42.0,
    glow: 14.0,
};

/// Master arcs (not in `MASTER` because a `Vec` constant cannot hold elements).
const MASTER_ARCS: [(f32, f32); 2] = [(81.0, 11.0), (115.0, 11.0)];

impl Geom {
    fn for_size(size: u32) -> Geom {
        let s = size as f32;
        let hinted = |margin, radius, x: [f32; 3], y: [f32; 3], t, arcs: Vec<(f32, f32)>, sweep| Geom {
            size: s,
            margin,
            radius,
            border: 1.0,
            stem_x0: x[0],
            stem_x1: x[1],
            bowl_cx: x[2],
            top: y[0],
            bowl_bottom: y[1],
            bottom: y[2],
            bowl_t: t,
            arcs,
            sweep_deg: sweep,
            glow: 0.0,
        };
        match size {
            16 => hinted(0.0, 3.5, [3.0, 6.0, 7.0], [3.0, 10.0, 13.0], 2.0, vec![(5.35, 0.9)], 45.0),
            20 => hinted(0.0, 4.25, [4.0, 7.0, 9.0], [4.0, 13.0, 16.0], 3.0, vec![(6.6, 1.0)], 45.0),
            24 => hinted(0.0, 5.0, [4.0, 8.0, 10.0], [5.0, 16.0, 19.0], 4.0, vec![(8.0, 1.2)], 45.0),
            32 => hinted(1.0, 6.5, [5.0, 10.0, 13.0], [6.0, 20.0, 26.0], 5.0, vec![(10.0, 1.3), (14.0, 1.3)], 38.0),
            _ => Self::scaled(size),
        }
    }

    fn scaled(size: u32) -> Geom {
        let k = size as f32 / MASTER.size;
        let snap = |v: f32| if size <= 48 { (v * k).round() } else { v * k };
        Geom {
            size: size as f32,
            margin: snap(MASTER.margin),
            radius: MASTER.radius * k,
            border: (MASTER.border * k).max(1.0),
            stem_x0: snap(MASTER.stem_x0),
            stem_x1: snap(MASTER.stem_x1),
            top: snap(MASTER.top),
            bottom: snap(MASTER.bottom),
            bowl_bottom: snap(MASTER.bowl_bottom),
            bowl_cx: snap(MASTER.bowl_cx),
            bowl_t: snap(MASTER.bowl_t),
            arcs: MASTER_ARCS.iter().map(|&(r, hw)| (r * k, hw * k)).collect(),
            sweep_deg: MASTER.sweep_deg,
            glow: if size >= 64 { MASTER.glow * k } else { 0.0 },
        }
    }

    fn bowl_center(&self) -> P2 {
        p2(self.bowl_cx, (self.top + self.bowl_bottom) * 0.5)
    }

    fn bowl_radius(&self) -> f32 {
        (self.bowl_bottom - self.top) * 0.5
    }

    fn badge(&self) -> Shape {
        let (m, s) = (self.margin, self.size);
        Shape::RoundRect { x0: m, y0: m, x1: s - m, y1: s - m, r: self.radius }
    }

    /// The "P": stem + bowl (rectangle joined to a half disc) minus the counter.
    fn glyph(&self) -> Shape {
        let c = self.bowl_center();
        let outer = Shape::Union(vec![
            Shape::rect(self.stem_x0, self.top, self.stem_x1, self.bottom),
            Shape::rect(self.stem_x0, self.top, self.bowl_cx, self.bowl_bottom),
            Shape::circle(c, self.bowl_radius()),
        ]);
        Shape::subtract(outer, self.glyph_counter())
    }

    /// The counter (hole) of the "P".
    fn glyph_counter(&self) -> Shape {
        let c = self.bowl_center();
        let r_in = (self.bowl_radius() - self.bowl_t).max(0.0);
        Shape::Union(vec![Shape::rect(self.stem_x1, c.y - r_in, self.bowl_cx, c.y + r_in), Shape::circle(c, r_in)])
    }

    /// Concentric "signal" arcs radiating from the bowl.
    fn signal(&self) -> Shape {
        let half = self.sweep_deg.to_radians();
        let c = self.bowl_center();
        Shape::Union(self.arcs.iter().map(|&(r, hw)| Shape::Arc { c, r, hw, a0: -half, a1: half }).collect())
    }

    /// Status dot of the stopped variant in the bottom-right corner (the empty quadrant of the
    /// "P"): (centre, radius, transparent gap around it). Its bounding box is pixel aligned.
    fn status_dot(&self) -> (P2, f32, f32) {
        let r = (self.size * 0.125 + 1.0).round();
        let gap = (self.size * 0.04).round().max(1.0);
        let c = self.size - r;
        (p2(c, c), r, gap)
    }

    /// Cyan "transmitter" dot in the counter of the "P" (large frames only; 0 = none).
    fn transmitter_radius(&self) -> f32 {
        if self.size >= 64.0 { (self.bowl_radius() - self.bowl_t) * 0.45 } else { 0.0 }
    }
}

struct Palette {
    badge_top: Rgba,
    badge_bottom: Rgba,
    gloss: Rgba,
    border_top: Rgba,
    border_bottom: Rgba,
    mark_top: Rgba,
    mark_bottom: Rgba,
    arc_top: Rgba,
    arc_bottom: Rgba,
    mark_glow: Rgba,
    arc_glow: Rgba,
}

const NORMAL_PALETTE: Palette = Palette {
    badge_top: rgb(0x18233F),
    badge_bottom: rgb(0x06080E),
    gloss: rgba(0x6F8FE0, 0.20),
    border_top: rgba(0x6A8AD0, 0.60),
    border_bottom: rgba(0x2B3B63, 0.50),
    mark_top: rgb(0xFF6A00),
    mark_bottom: rgb(0xFF3B30),
    arc_top: rgb(0x19E3FF),
    arc_bottom: rgb(0x19E3FF),
    mark_glow: rgba(0xFF4A1A, 0.45),
    arc_glow: rgba(0x19E3FF, 0.35),
};

const STOPPED_PALETTE: Palette = Palette {
    badge_top: rgb(0x343943),
    badge_bottom: rgb(0x16181D),
    gloss: rgba(0xC0C6D0, 0.12),
    border_top: rgba(0xA8B0BE, 0.55),
    border_bottom: rgba(0x5A6270, 0.45),
    mark_top: rgb(0xD2D7DF),
    mark_bottom: rgb(0x9DA4AF),
    arc_top: rgb(0x6B7280),
    arc_bottom: rgb(0x6B7280),
    mark_glow: rgba(0x000000, 0.0),
    arc_glow: rgba(0x000000, 0.0),
};

const STATUS_DOT_TOP: Rgba = rgb(0xFF5A4F);
const STATUS_DOT_BOTTOM: Rgba = rgb(0xE0261C);

/// All layers of one frame, back to front.
fn logo_layers(size: u32, variant: Variant) -> Vec<Layer> {
    let g = Geom::for_size(size);
    let pal = match variant {
        Variant::Normal => &NORMAL_PALETTE,
        Variant::Stopped => &STOPPED_PALETTE,
    };
    let dot = (variant == Variant::Stopped).then(|| g.status_dot());
    // The stopped variant cuts a transparent ring around the status dot out of everything below.
    let cut = |shape: Shape| match dot {
        Some((c, r, gap)) => Shape::subtract(shape, Shape::circle(c, r + gap)),
        None => shape,
    };
    let (top, bottom) = (g.margin, g.size - g.margin);
    let badge = g.badge();
    let mut layers =
        vec![Layer::fill(cut(badge.clone()), Paint::vertical(top, bottom, pal.badge_top, pal.badge_bottom))];
    if size >= 48 {
        let gloss = Paint::Radial {
            center: p2(g.size * 0.3, g.margin),
            radius: g.size * 0.85,
            c0: pal.gloss,
            c1: pal.gloss.with_alpha(0.0),
        };
        layers.push(Layer::fill(cut(badge.clone()), gloss));
    }
    let ring = Shape::subtract(badge.clone(), Shape::offset(badge, -g.border));
    layers.push(Layer::fill(cut(ring), Paint::vertical(top, bottom, pal.border_top, pal.border_bottom)));

    let glyph = g.glyph();
    let glyph_paint = Paint::vertical(g.top, g.bottom, pal.mark_top, pal.mark_bottom);
    match variant {
        Variant::Normal => {
            let signal = g.signal();
            let c = g.bowl_center();
            let reach = g.arcs.last().map_or(0.0, |a| a.0 + a.1);
            let arc_paint = Paint::vertical(c.y - reach, c.y + reach, pal.arc_top, pal.arc_bottom);
            if g.glow > 0.0 {
                // Neon halos, kept inside the badge.
                layers.push(Layer::glow(signal.clone(), pal.arc_glow, g.glow, g.badge()));
                layers.push(Layer::glow(glyph.clone(), pal.mark_glow, g.glow, g.badge()));
            }
            layers.push(Layer::fill(signal, arc_paint));
            layers.push(Layer::fill(glyph, glyph_paint));
            let tr = g.transmitter_radius();
            if tr > 0.0 {
                layers.push(Layer::glow(Shape::circle(c, tr), pal.arc_glow, g.glow * 0.6, g.glyph_counter()));
                layers.push(Layer::fill(Shape::circle(c, tr), arc_paint));
            }
        }
        Variant::Stopped => {
            layers.push(Layer::fill(cut(glyph), glyph_paint));
        }
    }
    if let Some((c, r, _)) = dot {
        let paint = Paint::vertical(c.y - r, c.y + r, STATUS_DOT_TOP, STATUS_DOT_BOTTOM);
        layers.push(Layer::fill(Shape::circle(c, r), paint));
    }
    layers
}

// ---------------------------------------------------------------------------------------------
// Contact sheet.
// ---------------------------------------------------------------------------------------------

const SHEET_ZOOMED: [u32; 3] = [16, 24, 32];
const SHEET_ZOOM: u32 = 8;
const SHEET_PAD: u32 = 16;
/// Windows 11 dark / light taskbar colours.
const SHEET_BACKGROUNDS: [[u8; 4]; 2] = [[0x1C, 0x1C, 0x1C, 0xFF], [0xF3, 0xF3, 0xF3, 0xFF]];

/// Zoomed 16/24/32 px frames (normal then stopped) on dark and light rows, plus 1:1 strips.
fn contact_sheet(normal: &[Image], off: &[Image]) -> AppResult<Image> {
    let cell_w: u32 = SHEET_ZOOMED.iter().map(|s| s * SHEET_ZOOM + SHEET_PAD).sum::<u32>() * 2;
    let width = SHEET_PAD + cell_w;
    let zoom_row = 32 * SHEET_ZOOM + 2 * SHEET_PAD;
    let strip_row = 64 + 2 * SHEET_PAD;
    let height = (zoom_row + strip_row) * 2;
    let mut sheet = Image::new(width, height);
    sheet.fill(SHEET_BACKGROUNDS[0]);
    for (row, bg) in SHEET_BACKGROUNDS.iter().enumerate() {
        let y0 = row as u32 * (zoom_row + strip_row);
        let mut band = Image::new(width, zoom_row + strip_row);
        band.fill(*bg);
        sheet.blit(&band, 0, y0, 1);
        let mut x = SHEET_PAD;
        for set in [normal, off] {
            for size in SHEET_ZOOMED {
                sheet.blit(find(set, size)?, x, y0 + SHEET_PAD, SHEET_ZOOM);
                x += size * SHEET_ZOOM + SHEET_PAD;
            }
        }
        let mut x = SHEET_PAD;
        let strip_y = y0 + zoom_row;
        for img in normal.iter().filter(|i| i.width <= 64).chain(off.iter()) {
            sheet.blit(img, x, strip_y, 1);
            x += img.width + SHEET_PAD;
        }
    }
    Ok(sheet)
}

// ---------------------------------------------------------------------------------------------
// PNG / zlib / ICO encoding.
// ---------------------------------------------------------------------------------------------

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
};

/// CRC-32 (ISO-HDLC) as used by PNG chunks.
fn crc32(parts: &[&[u8]]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for part in parts {
        for &b in *part {
            c = CRC_TABLE[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
        }
    }
    c ^ 0xFFFF_FFFF
}

/// Adler-32 checksum (zlib trailer).
fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let (mut a, mut b) = (1u32, 0u32);
    // 5552 is the largest block for which `b` cannot overflow before the modulo.
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += u32::from(x);
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

/// zlib stream (RFC 1950): header, raw DEFLATE from miniz_oxide, Adler-32 trailer.
fn zlib_compress(data: &[u8]) -> Vec<u8> {
    // CMF 0x78: deflate, 32 KiB window. FLG 0xDA: maximum compression, no dictionary,
    // (0x78 * 256 + 0xDA) % 31 == 0.
    let mut out = vec![0x78, 0xDA];
    out.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(data, 10));
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = i16::from(a) + i16::from(b) - i16::from(c);
    let (pa, pb, pc) = ((p - i16::from(a)).abs(), (p - i16::from(b)).abs(), (p - i16::from(c)).abs());
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

/// Applies PNG filter `kind` (0 None, 1 Sub, 2 Up, 3 Average, 4 Paeth) to one row.
fn filter_row(kind: u8, row: &[u8], prev: &[u8], bpp: usize, out: &mut Vec<u8>) {
    out.clear();
    for (i, (&x, &b)) in row.iter().zip(prev).enumerate() {
        let a = if i >= bpp { row[i - bpp] } else { 0 };
        let c = if i >= bpp { prev[i - bpp] } else { 0 };
        let predicted = match kind {
            0 => 0,
            1 => a,
            2 => b,
            3 => ((u16::from(a) + u16::from(b)) / 2) as u8,
            _ => paeth(a, b, c),
        };
        out.push(x.wrapping_sub(predicted));
    }
}

/// Encodes an RGBA8 image as PNG (colour type 6, adaptive per-row filters).
fn encode_png(img: &Image) -> Vec<u8> {
    const BPP: usize = 4;
    let stride = img.width as usize * BPP;
    let mut raw = Vec::with_capacity((stride + 1) * img.height as usize);
    let mut prev = vec![0u8; stride];
    let mut candidate = Vec::with_capacity(stride);
    let mut best = Vec::with_capacity(stride);
    for row in img.rgba.chunks_exact(stride.max(1)) {
        let mut best_kind = 0;
        let mut best_score = u64::MAX;
        for kind in 0..=4u8 {
            filter_row(kind, row, &prev, BPP, &mut candidate);
            // Minimum sum of absolute differences heuristic (libpng's default).
            let score: u64 = candidate.iter().map(|&v| u64::from((v as i8).unsigned_abs())).sum();
            if score < best_score {
                best_score = score;
                best_kind = kind;
                std::mem::swap(&mut best, &mut candidate);
            }
        }
        raw.push(best_kind);
        raw.extend_from_slice(&best);
        prev.copy_from_slice(row);
    }

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&img.width.to_be_bytes());
    ihdr.extend_from_slice(&img.height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8 bit, RGBA, deflate, adaptive filtering, no interlace

    let mut png = PNG_SIGNATURE.to_vec();
    write_chunk(&mut png, b"IHDR", &ihdr);
    write_chunk(&mut png, b"IDAT", &zlib_compress(&raw));
    write_chunk(&mut png, b"IEND", &[]);
    png
}

fn write_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    // Chunks here are far below 2 GiB; the cast cannot truncate.
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    out.extend_from_slice(&crc32(&[kind, data]).to_be_bytes());
}

/// Builds an `.ico` file whose frames are PNG images (supported by Windows Vista and later).
fn encode_ico(frames: &[Image]) -> AppResult<Vec<u8>> {
    let count = u16::try_from(frames.len()).map_err(|_| "too many icon frames")?;
    let pngs: Vec<Vec<u8>> = frames.iter().map(encode_png).collect();
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&1u16.to_le_bytes()); // type: icon
    out.extend_from_slice(&count.to_le_bytes());
    let mut offset = 6 + 16 * frames.len();
    for (img, png) in frames.iter().zip(&pngs) {
        if img.width != img.height || img.width == 0 || img.width > 256 {
            return Err(format!("invalid icon frame {}x{}", img.width, img.height).into());
        }
        let dim = if img.width == 256 { 0 } else { img.width as u8 };
        out.extend_from_slice(&[dim, dim, 0, 0]); // width, height, palette size, reserved
        out.extend_from_slice(&1u16.to_le_bytes()); // planes
        out.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
        out.extend_from_slice(&u32::try_from(png.len())?.to_le_bytes());
        out.extend_from_slice(&u32::try_from(offset)?.to_le_bytes());
        offset += png.len();
    }
    for png in &pngs {
        out.extend_from_slice(png);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------------------------

/// The `.res` writer of `build.rs`, so the generated icons are checked against the code that embeds
/// them.
#[cfg(test)]
#[allow(dead_code)]
#[path = "../build.rs"]
mod build_script;

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes a PNG produced by [`encode_png`] (verifies CRCs, zlib and all filter types).
    fn decode_png(png: &[u8]) -> Image {
        assert_eq!(&png[..8], &PNG_SIGNATURE);
        let mut pos = 8;
        let (mut width, mut height) = (0, 0);
        let mut idat = Vec::new();
        let mut kinds = Vec::new();
        while pos < png.len() {
            let len = u32::from_be_bytes(png[pos..pos + 4].try_into().unwrap()) as usize;
            let kind = &png[pos + 4..pos + 8];
            let data = &png[pos + 8..pos + 8 + len];
            let crc = u32::from_be_bytes(png[pos + 8 + len..pos + 12 + len].try_into().unwrap());
            assert_eq!(crc, crc32(&[kind, data]), "bad CRC");
            kinds.push(kind.to_vec());
            match kind {
                b"IHDR" => {
                    width = u32::from_be_bytes(data[0..4].try_into().unwrap());
                    height = u32::from_be_bytes(data[4..8].try_into().unwrap());
                    assert_eq!(&data[8..], &[8, 6, 0, 0, 0]);
                }
                b"IDAT" => idat.extend_from_slice(data),
                _ => {}
            }
            pos += 12 + len;
        }
        assert_eq!(kinds.first().map(Vec::as_slice), Some(&b"IHDR"[..]));
        assert_eq!(kinds.last().map(Vec::as_slice), Some(&b"IEND"[..]));
        let raw = miniz_oxide::inflate::decompress_to_vec_zlib(&idat).unwrap();
        let stride = width as usize * 4;
        assert_eq!(raw.len(), (stride + 1) * height as usize);
        let mut img = Image::new(width, height);
        let mut prev = vec![0u8; stride];
        for (y, line) in raw.chunks_exact(stride + 1).enumerate() {
            let kind = line[0];
            let mut cur = vec![0u8; stride];
            for i in 0..stride {
                let a = if i >= 4 { cur[i - 4] } else { 0 };
                let b = prev[i];
                let c = if i >= 4 { prev[i - 4] } else { 0 };
                let predicted = match kind {
                    0 => 0,
                    1 => a,
                    2 => b,
                    3 => ((u16::from(a) + u16::from(b)) / 2) as u8,
                    4 => paeth(a, b, c),
                    other => panic!("bad filter {other}"),
                };
                cur[i] = line[1 + i].wrapping_add(predicted);
            }
            img.rgba[y * stride..(y + 1) * stride].copy_from_slice(&cur);
            prev = cur;
        }
        img
    }

    fn noisy_image(w: u32, h: u32) -> Image {
        let mut img = Image::new(w, h);
        let mut state = 0x1234_5678u32;
        for (i, b) in img.rgba.iter_mut().enumerate() {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            // Mix smooth gradients (filters 1–4 win) with noise (filter 0 wins).
            *b = if i % 7 == 0 { (state >> 24) as u8 } else { (i / 4 % 97) as u8 };
        }
        img
    }

    #[test]
    fn checksums_match_reference_values() {
        assert_eq!(crc32(&[b"123456789"]), 0xCBF4_3926);
        assert_eq!(crc32(&[b"IEND"]), 0xAE42_6082);
        assert_eq!(crc32(&[b"1234", b"56789"]), 0xCBF4_3926);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        assert_eq!(adler32(&[]), 1);
        let big = vec![0xFFu8; 100_000];
        let (mut a, mut b) = (1u64, 0u64);
        for &x in &big {
            a = (a + u64::from(x)) % 65_521;
            b = (b + a) % 65_521;
        }
        assert_eq!(u64::from(adler32(&big)), (b << 16) | a);
    }

    #[test]
    fn zlib_stream_round_trips() {
        let data: Vec<u8> = (0..50_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let z = zlib_compress(&data);
        assert_eq!(((u16::from(z[0]) << 8) | u16::from(z[1])) % 31, 0);
        assert_eq!(miniz_oxide::inflate::decompress_to_vec_zlib(&z).unwrap(), data);
        assert_eq!(miniz_oxide::inflate::decompress_to_vec_zlib(&zlib_compress(&[])).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn png_round_trips() {
        for (w, h) in [(1, 1), (3, 5), (16, 16), (37, 11)] {
            let img = noisy_image(w, h);
            assert_eq!(decode_png(&encode_png(&img)), img);
        }
        let logo = render(24, &logo_layers(24, Variant::Normal));
        assert_eq!(decode_png(&encode_png(&logo)), logo);
    }

    #[test]
    fn paeth_matches_spec() {
        assert_eq!(paeth(10, 20, 10), 20);
        assert_eq!(paeth(20, 10, 10), 20);
        assert_eq!(paeth(10, 10, 20), 10);
        assert_eq!(paeth(0, 0, 0), 0);
    }

    #[test]
    fn signed_distances() {
        let c = Shape::circle(p2(10.0, 10.0), 5.0);
        assert!((c.sd(p2(10.0, 10.0)) + 5.0).abs() < 1e-5);
        assert!((c.sd(p2(18.0, 10.0)) - 3.0).abs() < 1e-5);
        let r = Shape::RoundRect { x0: 0.0, y0: 0.0, x1: 10.0, y1: 10.0, r: 2.0 };
        assert!(r.sd(p2(5.0, 5.0)) < 0.0);
        assert!(r.sd(p2(0.2, 0.2)) > 0.0, "rounded corner must be outside");
        assert!((r.sd(p2(5.0, 12.0)) - 2.0).abs() < 1e-5);

        let arc = Shape::Arc { c: p2(0.0, 0.0), r: 10.0, hw: 1.0, a0: -0.5, a1: 0.5 };
        assert!(arc.sd(p2(10.0, 0.0)) < 0.0);
        assert!(arc.sd(p2(-10.0, 0.0)) > 5.0, "opposite side is outside the sweep");
        assert!(arc.sd(p2(0.0, 0.0)) > 0.0);
        let ring = Shape::subtract(c.clone(), Shape::offset(c, -1.0));
        assert!(ring.sd(p2(10.0, 10.0)) > 0.0);
        assert!(ring.sd(p2(14.5, 10.0)) < 0.0);
    }

    #[test]
    fn wrap_angle_range() {
        for a in [-7.0f32, -PI, -1.0, 0.0, 1.0, PI, 4.0, 9.5] {
            let w = wrap_angle(a);
            assert!(w > -PI - 1e-5 && w <= PI + 1e-5, "{a} -> {w}");
            let turns = (a - w) / (2.0 * PI);
            assert!((turns - turns.round()).abs() < 1e-4, "{a} -> {w}");
        }
    }

    #[test]
    fn rasterizer_coverage_is_exact_on_pixel_edges() {
        let layer = Layer::fill(Shape::rect(1.0, 1.0, 3.0, 2.5), Paint::Solid(rgb(0xFF0000)));
        let img = render(4, &[layer]);
        assert_eq!(img.pixel(0, 0), [0, 0, 0, 0]);
        assert_eq!(img.pixel(1, 1), [255, 0, 0, 255]);
        assert_eq!(img.pixel(2, 1), [255, 0, 0, 255]);
        assert_eq!(img.pixel(1, 2), [255, 0, 0, 128], "half-covered pixel");
        assert_eq!(img.pixel(3, 1), [0, 0, 0, 0]);
    }

    #[test]
    fn compositing_is_source_over() {
        let below = Layer::fill(Shape::rect(0.0, 0.0, 2.0, 2.0), Paint::Solid(rgb(0x0000FF)));
        let above = Layer::fill(Shape::rect(0.0, 0.0, 2.0, 2.0), Paint::Solid(rgba(0xFF0000, 0.5)));
        let img = render(2, &[below, above]);
        assert_eq!(img.pixel(0, 0), [128, 0, 128, 255]);
    }

    #[test]
    fn hinted_geometry_is_on_the_pixel_grid() {
        for size in [16, 20, 24, 32, 40, 48] {
            let g = Geom::for_size(size);
            for v in [g.stem_x0, g.stem_x1, g.top, g.bottom, g.bowl_bottom, g.bowl_cx, g.margin, g.bowl_t] {
                assert_eq!(v, v.round(), "{size}px: {v} is not on the pixel grid");
            }
            // Straight counter edges land on whole pixels when the bowl radius and stroke allow it.
            let r_in = g.bowl_radius() - g.bowl_t;
            assert!(r_in >= 1.0, "{size}px: counter too small ({r_in})");
            assert!(g.stem_x1 - g.stem_x0 >= 3.0, "{size}px: stem thinner than 3 px");
            assert!(g.bottom - g.bowl_bottom >= 3.0, "{size}px: leg shorter than 3 px");
        }
    }

    #[test]
    fn artwork_fits_inside_the_badge() {
        for size in NORMAL_SIZES {
            let g = Geom::for_size(size);
            let inner = Shape::offset(g.badge(), -g.border);
            let signal = g.signal();
            let glyph = g.glyph();
            // Every sample inside the mark must also be inside the badge's inner area.
            let n = size * 4;
            for yi in 0..n {
                for xi in 0..n {
                    let p = p2((xi as f32 + 0.5) / 4.0, (yi as f32 + 0.5) / 4.0);
                    if signal.sd(p) < 0.0 || glyph.sd(p) < 0.0 {
                        assert!(inner.sd(p) < 0.0, "{size}px: mark leaves the badge at {p:?}");
                    }
                }
            }
            // The signal arcs never touch the glyph.
            let gap = g.arcs.first().map(|a| a.0 - a.1 - g.bowl_radius()).unwrap_or(f32::MAX);
            assert!(gap >= 0.85, "{size}px: arc gap {gap}");
        }
    }

    #[test]
    fn rendered_frames_look_sane() {
        for (variant, sizes) in [(Variant::Normal, &NORMAL_SIZES[..]), (Variant::Stopped, &OFF_SIZES[..])] {
            for &size in sizes {
                let img = render(size, &logo_layers(size, variant));
                assert_eq!((img.width, img.height), (size, size));
                let mid = size / 2;
                assert_eq!(img.pixel(mid, mid)[3], 255, "{size}px {variant:?}: centre must be opaque");
                assert!(img.pixel(0, 0)[3] < 128, "{size}px {variant:?}: corner must be rounded");
                let g = Geom::for_size(size);
                // Stem pixel: saturated red-orange (normal) or grey (stopped).
                let px = img.pixel(((g.stem_x0 + g.stem_x1) / 2.0) as u32, ((g.bowl_bottom + g.bottom) / 2.0) as u32);
                match variant {
                    Variant::Normal => assert!(px[0] > 200 && px[2] < 80, "{size}px stem colour {px:?}"),
                    Variant::Stopped => {
                        assert!(px[0].abs_diff(px[2]) < 40, "{size}px stem must be grey {px:?}")
                    }
                }
                if variant == Variant::Stopped {
                    let (c, _, _) = g.status_dot();
                    let dot = img.pixel(c.x as u32, c.y as u32);
                    assert!(dot[0] > 200 && dot[1] < 110 && dot[3] == 255, "{size}px status dot {dot:?}");
                }
            }
        }
    }

    #[test]
    fn ico_container_is_valid_and_embeddable() {
        // A synthetic 256 px frame keeps the test fast; it still exercises the "0 means 256" rule.
        let mut frames: Vec<Image> = [16u32, 48].iter().map(|&s| render(s, &logo_layers(s, Variant::Normal))).collect();
        frames.push(noisy_image(256, 256));
        let ico = encode_ico(&frames).unwrap();
        assert_eq!(&ico[..6], &[0, 0, 1, 0, 3, 0]);
        let parsed = build_script::res::parse_ico(&ico).unwrap();
        assert_eq!(parsed.iter().map(|i| i.width).collect::<Vec<_>>(), vec![16, 48, 0]);
        for (img, frame) in parsed.iter().zip(&frames) {
            assert_eq!((img.planes, img.bit_count), (1, 32));
            assert_eq!(&decode_png(&img.data), frame);
        }
        assert!(encode_ico(&[Image::new(300, 300)]).is_err());
        assert!(encode_ico(&[Image::new(16, 8)]).is_err());
    }

    #[test]
    fn checked_in_assets_embed_cleanly() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets");
        let normal = build_script::res::parse_ico(&fs::read(dir.join("predator.ico")).unwrap()).unwrap();
        let off = build_script::res::parse_ico(&fs::read(dir.join("predator-off.ico")).unwrap()).unwrap();
        let dims = |v: &[build_script::res::IconImage]| v.iter().map(|i| i.width).collect::<Vec<_>>();
        assert_eq!(dims(&normal), vec![16, 20, 24, 32, 40, 48, 64, 128, 0]);
        assert_eq!(dims(&off), vec![16, 20, 24, 32, 40, 48]);
        for img in normal.iter().chain(&off) {
            let decoded = decode_png(&img.data);
            let expected = if img.width == 0 { 256 } else { u32::from(img.width) };
            assert_eq!((decoded.width, decoded.height), (expected, expected));
        }
        let res = build_script::res::build_res(&[&normal, &off], b"version", b"manifest").unwrap();
        let parsed = build_script::res::parse_res(&res).unwrap();
        assert_eq!(parsed.iter().filter(|r| r.type_id == build_script::res::RT_ICON).count(), 15);
        assert_eq!(parsed.iter().filter(|r| r.type_id == build_script::res::RT_GROUP_ICON).count(), 2);
    }
}
