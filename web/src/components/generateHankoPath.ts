type Point = { x: number; y: number };
type Edge = { a: Point; b: Point };

export type HankoColorVariant = {
  name: string;
  color: string;
  kind: "solid" | "gradient";
};

export const ORIGINAL_HANKO_GRADIENT = "linear(#d64135,#b93028)";

function seededRandom(seed: string) {
  let state = 2166136261;
  for (const char of seed) {
    state ^= char.charCodeAt(0);
    state = Math.imul(state, 16777619);
  }
  return () => {
    state += 0x6d2b79f5;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

function hslHex(hue: number, saturation: number, lightness: number) {
  const h = ((hue % 360) + 360) % 360 / 60;
  const s = saturation / 100;
  const l = lightness / 100;
  const chroma = (1 - Math.abs(2 * l - 1)) * s;
  const x = chroma * (1 - Math.abs(h % 2 - 1));
  const offset = l - chroma / 2;
  const [red, green, blue] = h < 1 ? [chroma, x, 0]
    : h < 2 ? [x, chroma, 0]
      : h < 3 ? [0, chroma, x]
        : h < 4 ? [0, x, chroma]
          : h < 5 ? [x, 0, chroma]
            : [chroma, 0, x];
  return `#${[red, green, blue].map((channel) => Math.round((channel + offset) * 255).toString(16).padStart(2, "0")).join("")}`;
}

/** A seed-based palette made from golden-angle hues and related gradient pairs. */
export function generateHankoPalette(seed: string): HankoColorVariant[] {
  const random = seededRandom(`${seed}:colorways`);
  const base = random() * 360;
  const saturation = 64 + random() * 14;
  const lightness = 42 + random() * 8;
  const goldenAngle = 137.507764;
  const solids = Array.from({ length: 4 }, (_, index): HankoColorVariant => ({
    name: `Ink ${index + 1}`,
    kind: "solid",
    color: hslHex(base + goldenAngle * (index + 1), saturation - index * 1.5, lightness + (index % 2 ? 3 : 0)),
  }));
  const gradients = [0, 1, 2, 3].map((index): HankoColorVariant => {
    const center = base + goldenAngle * (index + 0.5);
    const spread = 24 + random() * 15;
    const first = hslHex(center - spread, saturation + 3, lightness - 2);
    const second = hslHex(center + spread, saturation - 4, lightness + 8);
    return { name: `Blend ${index + 1}`, kind: "gradient", color: `linear(${first},${second})` };
  });
  return [{ name: "Hanko original", kind: "gradient", color: ORIGINAL_HANKO_GRADIENT }, ...solids, ...gradients];
}

export function makeHankoSeed(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function generateHankoPath(seed: string): string {
  const size = 5;
  const center = Math.floor(size / 2);
  const random = seededRandom(seed);
  const symmetryRoll = random();
  const symmetry = symmetryRoll < 0.35 ? "vertical"
    : symmetryRoll < 0.60 ? "horizontal"
      : symmetryRoll < 0.80 ? "rotational" : "none";
  const point = (x: number, y: number): Point => ({ x, y });
  const node = (p: Point) => p.y * size + p.x;
  const fromNode = (n: number): Point => point(n % size, Math.floor(n / size));
  const edgeKey = (a: number, b: number) => a < b ? `${a}:${b}` : `${b}:${a}`;
  const edges = new Set<string>();
  const visited: number[] = [];
  const markVisited = (n: number) => {
    if (!visited.includes(n)) visited.push(n);
  };
  const neighbors = (n: number) => {
    const p = fromNode(n);
    return [[1, 0], [-1, 0], [0, 1], [0, -1]]
      .map(([dx, dy]) => point(p.x + dx, p.y + dy))
      .filter((q) => q.x >= 0 && q.x < size && q.y >= 0 && q.y < size);
  };
  const choose = <T,>(items: T[]): T => items[Math.floor(random() * items.length)];
  const start = choose([
    point(center, center), point(center - 1, center), point(center + 1, center),
    point(center, center - 1), point(center, center + 1),
  ]);
  let current = node(start);
  let previous: Point | null = null;
  markVisited(current);

  const steps = 10 + Math.floor(random() * 6);
  for (let i = 0; i < steps; i += 1) {
    if (visited.length > 1 && random() < 0.22) {
      current = choose(visited);
      previous = null;
    }
    const from = fromNode(current);
    const ranked = neighbors(current).map((next) => {
      const edge = edgeKey(current, node(next));
      let score = random();
      if (!edges.has(edge)) score += 1.2;
      if (previous) {
        const d1 = [from.x - previous.x, from.y - previous.y];
        const d2 = [next.x - from.x, next.y - from.y];
        if (d1[0] === d2[0] && d1[1] === d2[1]) score += 0.45;
      }
      score -= 0.03 * (Math.abs(next.x - center) + Math.abs(next.y - center));
      return { score, next };
    });
    ranked.sort((a, b) => b.score - a.score);
    const next = ranked[0].next;
    edges.add(edgeKey(current, node(next)));
    previous = from;
    current = node(next);
    markVisited(current);
  }

  const extraEdges = 1 + Math.floor(random() * 3);
  for (let i = 0; i < extraEdges; i += 1) {
    const fromId = choose(visited);
    const candidates = neighbors(fromId).filter((to) => !edges.has(edgeKey(fromId, node(to))));
    if (candidates.length) edges.add(edgeKey(fromId, node(choose(candidates))));
  }

  if (symmetry !== "none") {
    const original = [...edges];
    for (const key of original) {
      const [aId, bId] = key.split(":").map(Number);
      const reflect = (p: Point): Point => {
        if (symmetry === "vertical") return point(size - 1 - p.x, p.y);
        if (symmetry === "horizontal") return point(p.x, size - 1 - p.y);
        return point(size - 1 - p.x, size - 1 - p.y);
      };
      edges.add(edgeKey(node(reflect(fromNode(aId))), node(reflect(fromNode(bId)))));
    }
  }

  const allEdges: Edge[] = [...edges].map((key) => {
    const [a, b] = key.split(":").map(Number);
    return { a: fromNode(a), b: fromNode(b) };
  }).map(({ a, b }) => {
    const comesFirst = a.x < b.x || (a.x === b.x && a.y <= b.y);
    return comesFirst ? { a, b } : { a: b, b: a };
  }).sort((left, right) => left.a.x - right.a.x || left.a.y - right.a.y || left.b.x - right.b.x || left.b.y - right.b.y);

  const coordinate = (gridValue: number) => 278 + gridValue * 117;
  return allEdges.map(({ a, b }) => `M ${coordinate(a.x)} ${coordinate(a.y)} L ${coordinate(b.x)} ${coordinate(b.y)}`).join(" ");
}
