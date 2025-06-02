import { z } from "zod";

// User Schema
export const userSchema = z.object({
  id: z.string(),
  username: z.string(),
  password: z.string(),
  createdAt: z.date().optional()
});

export const insertUserSchema = userSchema.omit({ id: true, createdAt: true });

export type User = z.infer<typeof userSchema>;
export type InsertUser = z.infer<typeof insertUserSchema>;

// URL Check Schema
export const urlCheckSchema = z.object({
  id: z.string(),
  url: z.string().url(),
  isSafe: z.boolean(),
  result: z.string(),
  checkedAt: z.date()
});

export const insertUrlCheckSchema = urlCheckSchema.omit({ id: true, checkedAt: true });

export type UrlCheck = z.infer<typeof urlCheckSchema>;
export type InsertUrlCheck = z.infer<typeof insertUrlCheckSchema>;

// Phone Check Schema
export const phoneCheckSchema = z.object({
  id: z.string(),
  phoneNumber: z.string(),
  isSafe: z.boolean(),
  country: z.string().nullable(),
  carrier: z.string().nullable(),
  lineType: z.string().nullable(),
  riskScore: z.number().nullable(),
  details: z.record(z.any()).nullable(),
  checkedAt: z.date()
});

export const insertPhoneCheckSchema = phoneCheckSchema.omit({ id: true, checkedAt: true });

export type PhoneCheck = z.infer<typeof phoneCheckSchema>;
export type InsertPhoneCheck = z.infer<typeof insertPhoneCheckSchema>;
