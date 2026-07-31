import type { NextFunction, Request, Response } from 'express';
import { resolveSession } from './auth.js';
import { verifyAndBurn, type PowOp, type PowSubmission } from './pow.js';

declare module 'express-serve-static-core' {
  interface Request {
    username?: string;
  }
}

export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const header = req.header('authorization') ?? '';
  const token = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : undefined;
  const username = await resolveSession(token);
  if (!username) {
    res.status(401).json({ error: 'Invalid or expired session' });
    return;
  }
  req.username = username;
  next();
}

/** Express middleware factory enforcing a solved, unused PoW challenge for `op`. */
export function requirePow(op: PowOp) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const pow = req.body?.pow as PowSubmission | undefined;
    if (!verifyAndBurn(op, pow)) {
      res.status(403).json({ error: 'Proof of work missing, invalid, or already used' });
      return;
    }
    next();
  };
}
