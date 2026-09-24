#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

if (process.argv.length !== 4) {
  console.error("usage: node tools/extract-mermaid.js DOCS_DIR OUTPUT_DIR");
  process.exit(64);
}

const docs = path.resolve(process.argv[2]);
const output = path.resolve(process.argv[3]);
fs.rmSync(output, { recursive: true, force: true });
fs.mkdirSync(output, { recursive: true });
let count = 0;

function walk(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(target);
    else if (entry.isFile() && entry.name.endsWith(".md")) extract(target);
  }
}

function extract(file) {
  const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
  let diagram = null;
  let start = 0;
  for (let index = 0; index < lines.length; index += 1) {
    if (diagram === null && /^\s*```mermaid\s*$/.test(lines[index])) {
      diagram = [];
      start = index + 1;
    } else if (diagram !== null && /^\s*```\s*$/.test(lines[index])) {
      if (diagram.join("\n").trim() === "") throw new Error(`${file}:${start}: empty Mermaid block`);
      count += 1;
      fs.writeFileSync(path.join(output, `${String(count).padStart(3, "0")}.mmd`), `${diagram.join("\n")}\n`);
      diagram = null;
    } else if (diagram !== null) diagram.push(lines[index]);
  }
  if (diagram !== null) throw new Error(`${file}:${start}: unclosed Mermaid block`);
}

walk(docs);
if (count === 0) throw new Error("no Mermaid diagrams found");
console.log(`Extracted ${count} Mermaid diagrams.`);
