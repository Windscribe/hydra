//! How `hydra setup` looks: Windscribe's colours, the banner, cards and
//! country flags.
//!
//! Colours follow console's detection, so `NO_COLOR` and pipes turn them off.
//! True colour where the terminal says it has it, the nearest 256-colour shade
//! otherwise. Flags need a terminal that draws emoji; elsewhere the two-letter
//! country code takes their place, at the same width.

use dialoguer::console::{measure_text_width, Style, StyledObject, Term};
use dialoguer::theme::ColorfulTheme;

/// Windscribe's palette, from the website's `src/util/baseColors.ts`, each
/// with the nearest xterm-256 shade.
#[derive(Clone, Copy)]
pub enum Tone {
    Green,
    Blue,
    Turquoise,
    Yellow,
    Red,
    Dim,
}

impl Tone {
    fn rgb(self) -> (u8, u8, u8, u8) {
        match self {
            Tone::Green => (0x55, 0xff, 0x8a, 84),
            Tone::Blue => (0xc1, 0xe7, 0xed, 152),
            Tone::Turquoise => (0x3b, 0xff, 0xef, 86),
            Tone::Yellow => (0xf0, 0xe0, 0x50, 221),
            Tone::Red => (0xff, 0x55, 0x55, 203),
            // AUTH_TEXT_DIM: a colour rather than the dim attribute, which
            // some terminals ignore.
            Tone::Dim => (0x89, 0x8f, 0x9d, 245),
        }
    }

    pub fn style(self) -> Style {
        let s = Style::new().for_stderr();
        let (r, g, b, n) = self.rgb();
        if true_colour() {
            s.true_color(r, g, b)
        } else {
            s.color256(n)
        }
    }

    pub fn paint(self, text: impl Into<String>) -> StyledObject<String> {
        self.style().apply_to(text.into())
    }
}

fn true_colour() -> bool {
    Term::stderr().features().true_colors_supported()
}

pub fn bold(text: impl Into<String>) -> StyledObject<String> {
    Style::new().for_stderr().bold().apply_to(text.into())
}

/// Whether to draw emoji flags. `HYDRA_EMOJI=0` or `1` decides; otherwise a
/// UTF-8 locale on a terminal other than the Linux console.
pub fn wants_emoji() -> bool {
    match std::env::var("HYDRA_EMOJI").as_deref() {
        Ok("0") => return false,
        Ok("1") => return true,
        _ => {}
    }
    if std::env::var("TERM").is_ok_and(|t| t == "linux" || t == "dumb") {
        return false;
    }
    let utf8 = |var: &str| {
        std::env::var(var).is_ok_and(|v| v.to_uppercase().replace('-', "").contains("UTF8"))
    };
    Term::stderr().features().wants_emoji() || utf8("LC_ALL") || utf8("LC_CTYPE")
}

/// The flag for an ISO country code: regional indicator letters, which
/// terminals that draw emoji show as one flag two columns wide. Otherwise the
/// code itself, also two columns; two spaces for no code.
pub fn flag(code: &str, emoji: bool) -> String {
    let code = code.trim().to_ascii_uppercase();
    if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_uppercase()) {
        return "  ".into();
    }
    if !emoji {
        return code;
    }
    code.chars()
        .filter_map(|c| char::from_u32(0x1F1E6 + (c as u32 - 'A' as u32)))
        .collect()
}

/// A server's load, right-aligned in `width` digits: green when light,
/// yellow when busy, red near capacity.
pub fn load(percent: i64, width: usize) -> StyledObject<String> {
    let tone = match percent {
        p if p < 35 => Tone::Green,
        p if p < 70 => Tone::Yellow,
        _ => Tone::Red,
    };
    tone.paint(format!("{percent:>width$}%"))
}

pub fn arrow() -> StyledObject<String> {
    Tone::Turquoise.paint("→")
}

const WORDMARK: [&str; 6] = [
    "██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗ ",
    "██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗",
    "███████║ ╚████╔╝ ██║  ██║██████╔╝███████║",
    "██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║",
    "██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║",
    "╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝",
];

/// The hydra wordmark, Windscribe green fading to turquoise, and its line.
/// A one-line version on terminals too narrow for it.
pub fn banner() -> String {
    let cols = Term::stderr()
        .size_checked()
        .map_or(80, |(_, c)| usize::from(c));
    let tagline = format!(
        "{}  {}  {}",
        Tone::Blue.paint("a private WireGuard entry"),
        Tone::Dim.paint("·"),
        Tone::Dim.paint("for ").to_string() + &bold("windscribe").to_string()
    );
    if cols < 48 {
        let mark = Style::new()
            .for_stderr()
            .black()
            .on_color256(84)
            .bold()
            .apply_to(" hydra ");
        return format!("\n {mark}  {tagline}\n");
    }
    let (from, to) = ((0x55u8, 0xffu8, 0x8au8), (0x3bu8, 0xffu8, 0xefu8));
    let shades = [84u8, 84, 85, 85, 86, 86];
    let mut out = String::from("\n");
    for (i, row) in WORDMARK.iter().enumerate() {
        let style = Style::new().for_stderr();
        let style = if true_colour() {
            let t = i as f32 / (WORDMARK.len() - 1) as f32;
            let mix = |a: u8, b: u8| (f32::from(a) + (f32::from(b) - f32::from(a)) * t) as u8;
            style.true_color(mix(from.0, to.0), mix(from.1, to.1), mix(from.2, to.2))
        } else {
            style.color256(shades[i])
        };
        out += &format!("  {}\n", style.apply_to(row));
    }
    out += &format!("  {tagline}\n");
    out
}

/// `text` broken at spaces into lines that fit the terminal (at most 100
/// columns), each indented by `indent`.
pub fn wrap(text: &str, indent: usize) -> String {
    let cols = Term::stderr()
        .size_checked()
        .map_or(80, |(_, c)| usize::from(c))
        .min(100);
    let width = cols.saturating_sub(indent + 1).max(20);
    let mut lines: Vec<String> = vec![];
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && measure_text_width(&line) + 1 + measure_text_width(word) > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    let pad = " ".repeat(indent);
    lines
        .iter()
        .map(|l| format!("{pad}{l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A rounded box with a title and `key value` rows, drawn to fit its content.
pub fn card(title: &str, rows: &[(&str, String)]) -> String {
    let key_w = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let lines: Vec<String> = rows
        .iter()
        .map(|(k, v)| format!("{}  {v}", Tone::Dim.paint(format!("{k:<key_w$}"))))
        .collect();
    let title_w = measure_text_width(title);
    let w = lines
        .iter()
        .map(|l| measure_text_width(l))
        .max()
        .unwrap_or(0)
        .max(title_w + 3);
    let edge = |s: &str| Tone::Green.paint(s).to_string();
    let mut out = format!(
        "{}{}{}{}\n",
        edge("╭─ "),
        bold(title),
        edge(&format!(" {}", "─".repeat(w - title_w - 1))),
        edge("╮")
    );
    for l in &lines {
        let pad = " ".repeat(w - measure_text_width(l));
        out += &format!("{} {l}{pad} {}\n", edge("│"), edge("│"));
    }
    out += &format!("{}\n", edge(&format!("╰{}╯", "─".repeat(w + 2))));
    out
}

/// hydra's prompts in Windscribe's colours, Clack-style markers.
pub fn theme() -> ColorfulTheme {
    ColorfulTheme {
        defaults_style: Tone::Dim.style(),
        prompt_style: Style::new().for_stderr().bold(),
        prompt_prefix: Tone::Green.paint("◆"),
        prompt_suffix: Tone::Dim.paint("›"),
        success_prefix: Tone::Turquoise.paint("◇"),
        success_suffix: Tone::Dim.paint("·"),
        error_prefix: Tone::Red.paint("▲"),
        error_style: Tone::Red.style(),
        hint_style: Tone::Dim.style(),
        values_style: Tone::Green.style(),
        active_item_style: Style::new().for_stderr().bold(),
        inactive_item_style: Style::new().for_stderr(),
        active_item_prefix: Tone::Green.style().bold().apply_to("❯".to_string()),
        inactive_item_prefix: Style::new().for_stderr().apply_to(" ".to_string()),
        ..ColorfulTheme::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_are_regional_indicators_or_the_code() {
        assert_eq!(flag("ca", true), "🇨🇦");
        assert_eq!(flag("DE", true), "🇩🇪");
        assert_eq!(flag("DE", false), "DE");
        assert_eq!(flag("", true), "  ");
        assert_eq!(flag("USA", true), "  ");
        for f in [flag("ca", true), flag("CA", false), flag("", true)] {
            assert_eq!(measure_text_width(&f), 2, "{f:?}");
        }
    }

    #[test]
    fn cards_fit_their_widest_line() {
        let c = card(
            "hydra",
            &[("host", "vps-1".into()), ("entries", "2 forwarding".into())],
        );
        let widths: Vec<usize> = c.lines().map(measure_text_width).collect();
        assert!(widths.windows(2).all(|w| w[0] == w[1]), "{c}");
        assert!(c.contains("│ entries  2 forwarding │"), "{c}");
    }

    #[test]
    fn wrap_breaks_at_spaces_within_the_width() {
        let text = "word ".repeat(40);
        let wrapped = wrap(&text, 2);
        assert!(wrapped.lines().count() > 1);
        for l in wrapped.lines() {
            assert!(l.starts_with("  word"), "{l:?}");
            assert!(measure_text_width(l) <= 80, "{l:?}");
        }
        assert_eq!(wrap("one two", 0), "one two");
    }

    #[test]
    fn the_wordmark_rows_line_up() {
        let w = measure_text_width(WORDMARK[0]);
        assert!(WORDMARK.iter().all(|r| measure_text_width(r) == w));
    }
}
