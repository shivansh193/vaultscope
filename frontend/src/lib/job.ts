/** The capture the console is currently looking at, remembered across views. */

const KEY = "vaultscope.jobs";

export interface JobRecord {
  job_id: string;
  capture_file: string;
  session_count: number;
  fixture_mode: boolean;
  at: string;
}

export function rememberJob(job: Omit<JobRecord, "at">): void {
  const history = [{ ...job, at: new Date().toISOString() }, ...jobHistory()].slice(0, 10);
  sessionStorage.setItem(KEY, JSON.stringify(history));
}

export function jobHistory(): JobRecord[] {
  if (typeof sessionStorage === "undefined") return [];
  try {
    return JSON.parse(sessionStorage.getItem(KEY) ?? "[]") as JobRecord[];
  } catch {
    return [];
  }
}

export const currentJob = (): JobRecord | undefined => jobHistory()[0];
