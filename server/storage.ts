import { 
  collection,
  doc,
  getDoc,
  getDocs,
  query,
  where,
  orderBy,
  limit,
  addDoc,
  serverTimestamp
} from "firebase/firestore";
import { db } from "@shared/firebase";
import type { User, InsertUser, UrlCheck, InsertUrlCheck, PhoneCheck, InsertPhoneCheck } from "@shared/schema";

export interface IStorage {
  // User methods
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  // URL check methods
  createUrlCheck(check: InsertUrlCheck): Promise<UrlCheck>;
  getRecentUrlChecks(limit: number): Promise<UrlCheck[]>;
  
  // Phone check methods
  createPhoneCheck(check: InsertPhoneCheck): Promise<PhoneCheck>;
  getRecentPhoneChecks(limit: number): Promise<PhoneCheck[]>;
}

export class FirestoreStorage implements IStorage {
  // User methods
  async getUser(id: string): Promise<User | undefined> {
    const userDoc = await getDoc(doc(db, "users", id));
    return userDoc.exists() ? { id: userDoc.id, ...userDoc.data() } as User : undefined;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const q = query(collection(db, "users"), where("username", "==", username));
    const querySnapshot = await getDocs(q);
    if (querySnapshot.empty) return undefined;
    const doc = querySnapshot.docs[0];
    return { id: doc.id, ...doc.data() } as User;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const docRef = await addDoc(collection(db, "users"), {
      ...insertUser,
      createdAt: serverTimestamp()
    });
    return { id: docRef.id, ...insertUser } as User;
  }
  
  // URL check methods
  async createUrlCheck(check: InsertUrlCheck): Promise<UrlCheck> {
    const docRef = await addDoc(collection(db, "urlChecks"), {
      ...check,
      checkedAt: serverTimestamp()
    });
    return { id: docRef.id, ...check } as UrlCheck;
  }
  
  async getRecentUrlChecks(limitCount: number): Promise<UrlCheck[]> {
    const q = query(
      collection(db, "urlChecks"),
      orderBy("checkedAt", "desc"),
      limit(limitCount)
    );
    const querySnapshot = await getDocs(q);
    return querySnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }) as UrlCheck);
  }
  
  // Phone check methods
  async createPhoneCheck(check: InsertPhoneCheck): Promise<PhoneCheck> {
    const phoneCheckData = {
      ...check,
      country: check.country || null,
      carrier: check.carrier || null,
      lineType: check.lineType || null,
      riskScore: check.riskScore || null,
      details: check.details || null,
      checkedAt: serverTimestamp()
    };
    
    const docRef = await addDoc(collection(db, "phoneChecks"), phoneCheckData);
    return { id: docRef.id, ...phoneCheckData } as PhoneCheck;
  }
  
  async getRecentPhoneChecks(limitCount: number): Promise<PhoneCheck[]> {
    const q = query(
      collection(db, "phoneChecks"),
      orderBy("checkedAt", "desc"),
      limit(limitCount)
    );
    const querySnapshot = await getDocs(q);
    return querySnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }) as PhoneCheck);
  }
}

export const storage = new FirestoreStorage();
