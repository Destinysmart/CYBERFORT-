import { pgTable, text, serial, integer, boolean, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

export const urlChecks = pgTable("url_checks", {
  id: serial("id").primaryKey(),
  userId: text("user_id").notNull(),
  url: text("url").notNull(),
  isSafe: boolean("is_safe").notNull(),
  result: text("result").notNull(),
  checkedAt: timestamp("checked_at").defaultNow().notNull(),
});

export const insertUrlCheckSchema = createInsertSchema(urlChecks).pick({
  url: true,
  isSafe: true,
  result: true,
});

export type InsertUrlCheck = z.infer<typeof insertUrlCheckSchema>;
export type UrlCheck = typeof urlChecks.$inferSelect;

export const phoneChecks = pgTable("phone_checks", {
  id: serial("id").primaryKey(),
  userId: text("user_id").notNull(),
  phoneNumber: text("phone_number").notNull(),
  isSafe: boolean("is_safe").notNull(),
  country: text("country"),
  carrier: text("carrier"),
  lineType: text("line_type"),
  riskScore: integer("risk_score"),
  details: jsonb("details"),
  checkedAt: timestamp("checked_at").defaultNow().notNull(),
});

export const insertPhoneCheckSchema = createInsertSchema(phoneChecks).pick({
  phoneNumber: true,
  isSafe: true,
  country: true,
  carrier: true,
  lineType: true,
  riskScore: true,
  details: true,
});

export type InsertPhoneCheck = z.infer<typeof insertPhoneCheckSchema>;
export type PhoneCheck = typeof phoneChecks.$inferSelect;
