# Setting Up a Node.js Project with TypeScript

## 1. Initialize the Project
```sh
mkdir my-node-ts-app && cd my-node-ts-app
npm init -y
```
This will create a `package.json` file.

---

## 2. Install TypeScript and Required Dependencies
```sh
npm install --save-dev typescript ts-node @types/node
```
- `typescript`: The TypeScript compiler.
- `ts-node`: Allows running TypeScript directly without compiling.
- `@types/node`: Type definitions for Node.js.

---

## 3. Initialize TypeScript Configuration
```sh
npx tsc --init
```
This will create a `tsconfig.json` file. Modify it as needed:

### Recommended `tsconfig.json`
```json
{
  "compilerOptions": {
    "target": "ES6",
    "module": "CommonJS",
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true
  }
}
```

---

## 4. Create Source Directory
```sh
mkdir src
```
Inside the `src` folder, create a sample `index.ts` file:

### `src/index.ts`
```ts
console.log("Hello, TypeScript with Node.js!");
```

---

## 5. Run the Project
Use `ts-node` to run the TypeScript file:
```sh
npx ts-node src/index.ts
```

---

## 6. Build and Run (Compiled Version)
To compile the TypeScript code to JavaScript:
```sh
npx tsc
```
This generates JavaScript files inside the `dist` folder.

Run the compiled JavaScript file using Node.js:
```sh
node dist/index.js
```

---

## 7. Setup Scripts in `package.json`
Modify `package.json` to add useful scripts:
```json
"scripts": {
  "start": "node dist/index.js",
  "build": "tsc",
  "dev": "ts-node src/index.ts"
}
```
Now you can run:
- `npm run dev` → Run TypeScript file directly.
- `npm run build` → Compile TypeScript to JavaScript.
- `npm start` → Run the compiled JavaScript.

---

## 8. Optional: Install Express with TypeScript (For Web Apps)
If you want to build a web server:
```sh
npm install express
npm install --save-dev @types/express
```
Create `src/server.ts`:
```ts
import express from "express";

const app = express();
const PORT = 3000;

app.get("/", (req, res) => {
  res.send("Hello, Express with TypeScript!");
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
```
Run with:
```sh
npx ts-node src/server.ts
```

---

## Done! 🎉
You now have a **Node.js + TypeScript** project set up and running! 🚀
