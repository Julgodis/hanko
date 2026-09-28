use std::collections::HashSet;

// Mirrors web/src/components/generateHankoPath.ts so the public picture URL
// shows the exact glyph produced by the user's stamp seed.

#[derive(Clone, Copy)]
struct Point {
    x: i32,
    y: i32,
}

struct SeededRandom {
    state: u32,
}

impl SeededRandom {
    fn new(seed: &str) -> Self {
        let mut state = 2_166_136_261_u32;
        for byte in seed.bytes() {
            state ^= u32::from(byte);
            state = state.wrapping_mul(16_777_619);
        }
        Self { state }
    }

    fn next(&mut self) -> f64 {
        self.state = self.state.wrapping_add(0x6d2b79f5);
        let mut value = self.state;
        value = (value ^ (value >> 15)).wrapping_mul(value | 1);
        value ^= value.wrapping_add((value ^ (value >> 7)).wrapping_mul(value | 61));
        f64::from(value ^ (value >> 14)) / 4_294_967_296.0
    }
}

fn choose<T: Copy>(random: &mut SeededRandom, items: &[T]) -> T {
    items[(random.next() * items.len() as f64) as usize]
}

fn point(node: usize) -> Point {
    Point {
        x: (node % 5) as i32,
        y: (node / 5) as i32,
    }
}

fn node(point: Point) -> usize {
    (point.y * 5 + point.x) as usize
}

fn neighbors(node_id: usize) -> Vec<usize> {
    let current = point(node_id);
    [(1, 0), (-1, 0), (0, 1), (0, -1)]
        .into_iter()
        .map(|(dx, dy)| Point {
            x: current.x + dx,
            y: current.y + dy,
        })
        .filter(|next| (0..5).contains(&next.x) && (0..5).contains(&next.y))
        .map(node)
        .collect()
}

fn insert_edge(
    edges: &mut Vec<(usize, usize)>,
    edge_set: &mut HashSet<(usize, usize)>,
    a: usize,
    b: usize,
) {
    let edge = if a < b { (a, b) } else { (b, a) };
    if edge_set.insert(edge) {
        edges.push(edge);
    }
}

fn generate_hanko_path(seed: &str) -> String {
    let mut random = SeededRandom::new(seed);
    let symmetry_roll = random.next();
    let symmetry = if symmetry_roll < 0.35 {
        0
    } else if symmetry_roll < 0.60 {
        1
    } else if symmetry_roll < 0.80 {
        2
    } else {
        3
    };
    let starts = [12, 11, 13, 7, 17];
    let mut edges = Vec::new();
    let mut edge_set = HashSet::new();
    let mut visited = Vec::new();
    let mut current = choose(&mut random, &starts);
    let mut previous = None;
    visited.push(current);

    let steps = 10 + (random.next() * 6.0) as usize;
    for _ in 0..steps {
        if visited.len() > 1 && random.next() < 0.22 {
            current = choose(&mut random, &visited);
            previous = None;
        }
        let from = point(current);
        let mut ranked: Vec<(f64, usize)> = neighbors(current)
            .into_iter()
            .map(|next| {
                let edge = if current < next {
                    (current, next)
                } else {
                    (next, current)
                };
                let mut score = random.next();
                if !edge_set.contains(&edge) {
                    score += 1.2;
                }
                if let Some(previous) = previous {
                    let previous: Point = point(previous);
                    let d1 = (from.x - previous.x, from.y - previous.y);
                    let next_point = point(next);
                    let d2 = (next_point.x - from.x, next_point.y - from.y);
                    if d1 == d2 {
                        score += 0.45;
                    }
                }
                let next_point = point(next);
                score -= 0.03 * f64::from((next_point.x - 2).abs() + (next_point.y - 2).abs());
                (score, next)
            })
            .collect();
        ranked.sort_by(|left, right| right.0.total_cmp(&left.0));
        let next = ranked[0].1;
        insert_edge(&mut edges, &mut edge_set, current, next);
        previous = Some(current);
        current = next;
        if !visited.contains(&current) {
            visited.push(current);
        }
    }

    let extra_edges = 1 + (random.next() * 3.0) as usize;
    for _ in 0..extra_edges {
        let from = choose(&mut random, &visited);
        let candidates: Vec<usize> = neighbors(from)
            .into_iter()
            .filter(|to| {
                let edge = if from < *to { (from, *to) } else { (*to, from) };
                !edge_set.contains(&edge)
            })
            .collect();
        if !candidates.is_empty() {
            let to = choose(&mut random, &candidates);
            insert_edge(&mut edges, &mut edge_set, from, to);
        }
    }

    if symmetry != 3 {
        let original_edges = edges.clone();
        for (a, b) in original_edges {
            let reflect = |point: Point| match symmetry {
                0 => Point {
                    x: 4 - point.x,
                    y: point.y,
                },
                1 => Point {
                    x: point.x,
                    y: 4 - point.y,
                },
                _ => Point {
                    x: 4 - point.x,
                    y: 4 - point.y,
                },
            };
            insert_edge(
                &mut edges,
                &mut edge_set,
                node(reflect(point(a))),
                node(reflect(point(b))),
            );
        }
    }

    let mut paths: Vec<(Point, Point)> = edges
        .into_iter()
        .map(|(a, b)| {
            let (a, b) = (point(a), point(b));
            if a.x < b.x || (a.x == b.x && a.y <= b.y) {
                (a, b)
            } else {
                (b, a)
            }
        })
        .collect();
    paths.sort_by_key(|(a, b)| (a.x, a.y, b.x, b.y));
    paths
        .into_iter()
        .map(|(a, b)| {
            let coordinate = |value: i32| 278 + value * 117;
            format!(
                "M {} {} L {} {}",
                coordinate(a.x),
                coordinate(a.y),
                coordinate(b.x),
                coordinate(b.y)
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn valid_hex_color(color: &str) -> bool {
    color.len() == 7
        && color.starts_with('#')
        && color[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn ink(color: &str) -> (String, String) {
    if let Some(stops) = color
        .strip_prefix("linear(")
        .and_then(|color| color.strip_suffix(')'))
        && let Some((first, second)) = stops.split_once(',')
        && valid_hex_color(first)
        && valid_hex_color(second)
    {
        return (
            "url(#ink-gradient)".to_owned(),
            format!(
                "<defs><linearGradient id=\"ink-gradient\" x1=\"0%\" y1=\"0%\" x2=\"100%\" y2=\"100%\"><stop offset=\"0%\" stop-color=\"{first}\"/><stop offset=\"100%\" stop-color=\"{second}\"/></linearGradient></defs>"
            ),
        );
    }
    let solid = if valid_hex_color(color) {
        color
    } else {
        "#d64135"
    };
    (solid.to_owned(), String::new())
}

pub fn render_picture(color: &str, seed: &str) -> String {
    let (paint, defs) = ink(color);
    let path = generate_hanko_path(seed);
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 1024 1024\">{defs}<g fill=\"none\" stroke=\"{paint}\" stroke-width=\"76\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><rect x=\"122\" y=\"122\" width=\"780\" height=\"780\" rx=\"132\"/><path d=\"{path}\"/></g><g fill=\"{paint}\"><circle cx=\"92\" cy=\"510\" r=\"9\"/><circle cx=\"936\" cy=\"474\" r=\"7\"/><circle cx=\"900\" cy=\"852\" r=\"5\"/><circle cx=\"154\" cy=\"176\" r=\"5\"/><circle cx=\"836\" cy=\"126\" r=\"4\"/><circle cx=\"214\" cy=\"904\" r=\"6\"/><circle cx=\"758\" cy=\"930\" r=\"4\"/></g></svg>"
    )
}

pub fn picture_url(issuer: &str, user_id: &str) -> String {
    format!("{issuer}/api/users/{user_id}/picture.svg")
}
