declare module "*.html" {
  const content: string;
  export default content;
}

declare module "*.sql?raw" {
  const content: string;
  export default content;
}

declare module "*.html?raw" {
  const content: string;
  export default content;
}
