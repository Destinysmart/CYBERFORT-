import { 
  users, type User, type InsertUser,
  urlChecks, type UrlCheck, type InsertUrlCheck,
  phoneChecks, type PhoneCheck, type InsertPhoneCheck
} from "@shared/schema";
import { db } from "./db";
import { eq, desc } from "drizzle-orm";

export interface IStorage {
  // User methods
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  // URL check methods
  createUrlCheck(check: InsertUrlCheck): Promise<UrlCheck>;
  getRecentUrlChecks(limit: number): Promise<UrlCheck[]>;
  
  // Phone check methods
  createPhoneCheck(check: InsertPhoneCheck): Promise<PhoneCheck>;
  getRecentPhoneChecks(limit: number): Promise<PhoneCheck[]>;
}

export class DatabaseStorage implements IStorage {
  // User methods
  async getUser(id: number): Promise<User | undefined> {
    const results = await db.select().from(users).where(eq(users.id, id));
    return results.length > 0 ? results[0] : undefined;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const results = await db.select().from(users).where(eq(users.username, username));
    return results.length > 0 ? results[0] : undefined;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const result = await db.insert(users).values(insertUser).returning();
    return result[0];
  }
  
  // URL check methods
  async createUrlCheck(check: InsertUrlCheck): Promise<UrlCheck> {
    const result = await db.insert(urlChecks).values(check).returning();
    return result[0];
  }
  
  async getRecentUrlChecks(limit: number): Promise<UrlCheck[]> {
    return await db.select().from(urlChecks).orderBy(desc(urlChecks.checkedAt)).limit(limit);
  }
  
  // Phone check methods
  async createPhoneCheck(check: InsertPhoneCheck): Promise<PhoneCheck> {
    // Ensure all optional fields have null values if not provided
    const phoneCheckData = {
      ...check,
      country: check.country || null,
      carrier: check.carrier || null,
      lineType: check.lineType || null,
      riskScore: check.riskScore || null,
      details: check.details || null
    };
    
    const result = await db.insert(phoneChecks).values(phoneCheckData).returning();
    return result[0];
  }
  
  async getRecentPhoneChecks(limit: number): Promise<PhoneCheck[]> {
    return await db.select().from(phoneChecks).orderBy(desc(phoneChecks.checkedAt)).limit(limit);
  }
}

export const storage = new DatabaseStorage();
