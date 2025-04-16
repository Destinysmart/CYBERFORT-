import { 
  users, type User, type InsertUser,
  urlChecks, type UrlCheck, type InsertUrlCheck,
  phoneChecks, type PhoneCheck, type InsertPhoneCheck
} from "@shared/schema";

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

export class MemStorage implements IStorage {
  private users: Map<number, User>;
  private urlChecks: Map<number, UrlCheck>;
  private phoneChecks: Map<number, PhoneCheck>;
  private userIdCounter: number;
  private urlCheckIdCounter: number;
  private phoneCheckIdCounter: number;

  constructor() {
    this.users = new Map();
    this.urlChecks = new Map();
    this.phoneChecks = new Map();
    this.userIdCounter = 1;
    this.urlCheckIdCounter = 1;
    this.phoneCheckIdCounter = 1;
  }

  // User methods
  async getUser(id: number): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username,
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = this.userIdCounter++;
    const user: User = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }
  
  // URL check methods
  async createUrlCheck(check: InsertUrlCheck): Promise<UrlCheck> {
    const id = this.urlCheckIdCounter++;
    const now = new Date();
    const urlCheck: UrlCheck = { 
      ...check, 
      id, 
      checkedAt: now 
    };
    this.urlChecks.set(id, urlCheck);
    return urlCheck;
  }
  
  async getRecentUrlChecks(limit: number): Promise<UrlCheck[]> {
    return Array.from(this.urlChecks.values())
      .sort((a, b) => new Date(b.checkedAt).getTime() - new Date(a.checkedAt).getTime())
      .slice(0, limit);
  }
  
  // Phone check methods
  async createPhoneCheck(check: InsertPhoneCheck): Promise<PhoneCheck> {
    const id = this.phoneCheckIdCounter++;
    const now = new Date();
    const phoneCheck: PhoneCheck = { 
      ...check, 
      id, 
      checkedAt: now,
      // Ensure null values for optional fields
      country: check.country || null,
      carrier: check.carrier || null,
      lineType: check.lineType || null,
      riskScore: check.riskScore || null,
      details: check.details || null
    };
    this.phoneChecks.set(id, phoneCheck);
    return phoneCheck;
  }
  
  async getRecentPhoneChecks(limit: number): Promise<PhoneCheck[]> {
    return Array.from(this.phoneChecks.values())
      .sort((a, b) => new Date(b.checkedAt).getTime() - new Date(a.checkedAt).getTime())
      .slice(0, limit);
  }
}

export const storage = new MemStorage();
