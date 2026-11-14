import { readdirSync, readFileSync } from 'node:fs'
import ts from 'typescript'
import schema from '../axi-credential.schema.json' with { type: 'json' }

const names = new Set(Object.entries(schema.properties).filter(([, property]) => 'x-secret' in property).map(([name]) => name))
const root = new URL('../src/', import.meta.url)
for (const file of readdirSync(root, { recursive: true })) {
  if (typeof file !== 'string' || !file.endsWith('.ts') || file === 'profile.ts') continue
  const source = ts.createSourceFile(file, readFileSync(new URL(file, root), 'utf8'), ts.ScriptTarget.Latest, true)
  const secretName = (node: ts.Node): boolean => (ts.isIdentifier(node) || ts.isStringLiteral(node)) && names.has(node.text)
  const containsSecretName = (node: ts.Node): boolean => secretName(node) || ts.forEachChild(node, containsSecretName) === true
  const visit = (node: ts.Node): void => {
    if (ts.isIdentifier(node) && node.text === 'resolveSecret'
      || ts.isArrayLiteralExpression(node) && node.elements.some(containsSecretName)) {
      const { line } = source.getLineAndCharacterOfPosition(node.getStart(source))
      throw new Error(`${file}:${line + 1}: derive protected secret lists through profileSecrets()`)
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
}
