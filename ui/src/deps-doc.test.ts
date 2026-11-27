// docs/ui-dependencies.md must list every package in ui/package.json with its installed version.
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

const ui = path.resolve(import.meta.dirname, '..')
const pkg = JSON.parse(readFileSync(path.join(ui, 'package.json'), 'utf8'))
const lock = JSON.parse(readFileSync(path.join(ui, 'package-lock.json'), 'utf8'))
const doc = readFileSync(path.resolve(ui, '../docs/ui-dependencies.md'), 'utf8')

describe('docs/ui-dependencies.md', () => {
  const all = { ...pkg.dependencies, ...pkg.devDependencies } as Record<string, string>
  for (const name of Object.keys(all)) {
    it(`lists ${name} with its locked version`, () => {
      const version = lock.packages[`node_modules/${name}`].version
      expect(doc).toContain(`| ${name} | ${version} |`)
    })
  }
})
