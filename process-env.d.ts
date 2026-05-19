/** Minimal typing when @types/node is not installed yet */
declare module "node:process" {
  interface Process {
    env: Record<string, string | undefined>;
  }
  const process: Process;
  export default process;
}
