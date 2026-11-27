// Compares two PNG files pixel by pixel in headless Chromium (no extra package).
// Prints JSON: size of each image, count of differing pixels, the bounding box of the differing pixels and
// the largest difference in any colour channel (0-255). Used by e2e/compare-unchanged.sh.
// Usage: node e2e/pixel-diff.mjs a.png b.png

import { readFileSync } from 'node:fs'
import { chromium } from '@playwright/test'

const [a, b] = process.argv.slice(2)
const browser = await chromium.launch()
const page = await browser.newPage()
const result = await page.evaluate(
  async ([x, y]) => {
    const load = (s) =>
      new Promise((ok) => {
        const img = new Image()
        img.onload = () => ok(img)
        img.src = 'data:image/png;base64,' + s
      })
    const [i1, i2] = await Promise.all([load(x), load(y)])
    const pixels = (img) => {
      const cv = document.createElement('canvas')
      cv.width = img.width
      cv.height = img.height
      const g = cv.getContext('2d')
      g.drawImage(img, 0, 0)
      return g.getImageData(0, 0, img.width, img.height).data
    }
    const out = { size: [i1.width, i1.height], size2: [i2.width, i2.height], pixels: 0, box: null, max: 0 }
    if (i1.width !== i2.width || i1.height !== i2.height) return out
    const d1 = pixels(i1)
    const d2 = pixels(i2)
    let [x0, y0, x1, y1] = [Infinity, Infinity, -1, -1]
    for (let k = 0; k < d1.length; k += 4) {
      const dd = Math.max(Math.abs(d1[k] - d2[k]), Math.abs(d1[k + 1] - d2[k + 1]), Math.abs(d1[k + 2] - d2[k + 2]), Math.abs(d1[k + 3] - d2[k + 3]))
      if (!dd) continue
      out.pixels++
      out.max = Math.max(out.max, dd)
      const px = (k / 4) % i1.width
      const py = Math.floor(k / 4 / i1.width)
      x0 = Math.min(x0, px)
      y0 = Math.min(y0, py)
      x1 = Math.max(x1, px)
      y1 = Math.max(y1, py)
    }
    if (out.pixels) out.box = [x0, y0, x1, y1]
    return out
  },
  [readFileSync(a).toString('base64'), readFileSync(b).toString('base64')],
)
console.log(JSON.stringify(result))
await browser.close()
