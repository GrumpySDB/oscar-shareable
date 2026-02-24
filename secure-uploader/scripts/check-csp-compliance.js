const fs = require('fs');
const path = require('path');

const publicDir = path.join(__dirname, '..', 'public');
const htmlFiles = fs.readdirSync(publicDir).filter((name) => name.endsWith('.html'));

const violations = [];

for (const fileName of htmlFiles) {
  const filePath = path.join(publicDir, fileName);
  const content = fs.readFileSync(filePath, 'utf8');

  const inlineScriptPattern = /<script(?![^>]*\bsrc\b)[^>]*>[\s\S]*?<\/script>/gi;
  if (inlineScriptPattern.test(content)) {
    violations.push(`${fileName}: contains inline <script> block`);
  }

  const inlineHandlerPattern = /\son[a-z]+\s*=\s*(['"]).*?\1/gi;
  if (inlineHandlerPattern.test(content)) {
    violations.push(`${fileName}: contains inline event handler attribute`);
  }
}

if (violations.length > 0) {
  console.error('CSP compliance check failed:');
  for (const violation of violations) {
    console.error(`- ${violation}`);
  }
  process.exit(1);
}

console.log(`CSP compliance check passed for ${htmlFiles.length} HTML file(s).`);
