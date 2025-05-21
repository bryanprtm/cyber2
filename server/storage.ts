import { 
  users, 
  tools, 
  scanResults, 
  sessions, 
  toolExecutionLog, 
  userFavorites,
  type User, 
  type InsertUser,
  type Tool,
  type InsertTool,
  type ScanResult,
  type InsertScanResult,
  type Session,
  type InsertSession,
  type ToolExecutionLog,
  type InsertToolExecutionLog,
  type UserFavorite,
  type InsertUserFavorite
} from "@shared/schema";
import { db } from "./db";
import { eq, and, desc } from "drizzle-orm";

// Interface for database storage operations
export interface IStorage {
  // User methods
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  updateUserLastLogin(id: number): Promise<User | undefined>;
  
  // Tool methods
  getTool(id: string): Promise<Tool | undefined>;
  getAllTools(activeOnly?: boolean): Promise<Tool[]>;
  getToolsByCategory(category: string): Promise<Tool[]>;
  createTool(tool: InsertTool): Promise<Tool>;
  updateTool(id: string, updates: Partial<InsertTool>): Promise<Tool | undefined>;
  
  // Scan results methods
  getScanResult(id: number): Promise<ScanResult | undefined>;
  getScanResultsByUser(userId: number): Promise<ScanResult[]>;
  getScanResultsByTool(toolId: string): Promise<ScanResult[]>;
  createScanResult(result: InsertScanResult): Promise<ScanResult>;
  
  // Session methods
  getSession(id: string): Promise<Session | undefined>;
  createSession(session: InsertSession): Promise<Session>;
  deleteSession(id: string): Promise<boolean>;
  
  // Tool execution log methods
  getToolExecutionLogs(userId: number): Promise<ToolExecutionLog[]>;
  createToolExecutionLog(log: InsertToolExecutionLog): Promise<ToolExecutionLog>;
  
  // User favorites methods
  getUserFavorites(userId: number): Promise<UserFavorite[]>;
  addUserFavorite(favorite: InsertUserFavorite): Promise<UserFavorite>;
  removeUserFavorite(userId: number, toolId: string): Promise<boolean>;
}

// Database Storage Implementation
export class DatabaseStorage implements IStorage {
  // User methods
  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id)).limit(1);
    return user;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.username, username))
      .limit(1);
    return user;
  }

  async createUser(user: InsertUser): Promise<User> {
    const [newUser] = await db
      .insert(users)
      .values(user)
      .returning();
    return newUser;
  }

  async updateUserLastLogin(id: number): Promise<User | undefined> {
    const [updatedUser] = await db
      .update(users)
      .set({ lastLogin: new Date() })
      .where(eq(users.id, id))
      .returning();
    return updatedUser;
  }
  
  // Tool methods
  async getTool(id: string): Promise<Tool | undefined> {
    const [tool] = await db
      .select()
      .from(tools)
      .where(eq(tools.toolId, id))
      .limit(1);
    return tool;
  }

  async getAllTools(activeOnly: boolean = true): Promise<Tool[]> {
    if (activeOnly) {
      return db.select().from(tools).where(eq(tools.active, true));
    }
    return db.select().from(tools);
  }

  async getToolsByCategory(category: string): Promise<Tool[]> {
    return db
      .select()
      .from(tools)
      .where(and(eq(tools.category, category), eq(tools.active, true)));
  }

  async createTool(tool: InsertTool): Promise<Tool> {
    const [newTool] = await db.insert(tools).values(tool).returning();
    return newTool;
  }

  async updateTool(id: string, updates: Partial<InsertTool>): Promise<Tool | undefined> {
    const [updatedTool] = await db
      .update(tools)
      .set(updates)
      .where(eq(tools.toolId, id))
      .returning();
    return updatedTool;
  }
  
  // Scan results methods
  async getScanResult(id: number): Promise<ScanResult | undefined> {
    const [result] = await db
      .select()
      .from(scanResults)
      .where(eq(scanResults.id, id))
      .limit(1);
    return result;
  }

  async getScanResultsByUser(userId: number): Promise<ScanResult[]> {
    return db
      .select()
      .from(scanResults)
      .where(eq(scanResults.userId, userId))
      .orderBy(desc(scanResults.scanTime));
  }

  async getScanResultsByTool(toolId: string): Promise<ScanResult[]> {
    return db
      .select()
      .from(scanResults)
      .where(eq(scanResults.toolId, toolId))
      .orderBy(desc(scanResults.scanTime));
  }

  async createScanResult(result: InsertScanResult): Promise<ScanResult> {
    const [newResult] = await db
      .insert(scanResults)
      .values(result)
      .returning();
    return newResult;
  }
  
  // Session methods
  async getSession(id: string): Promise<Session | undefined> {
    const [session] = await db
      .select()
      .from(sessions)
      .where(eq(sessions.id, id))
      .limit(1);
    return session;
  }

  async createSession(session: InsertSession): Promise<Session> {
    const [newSession] = await db
      .insert(sessions)
      .values(session)
      .returning();
    return newSession;
  }

  async deleteSession(id: string): Promise<boolean> {
    const result = await db
      .delete(sessions)
      .where(eq(sessions.id, id))
      .returning({ id: sessions.id });
    return result.length > 0;
  }
  
  // Tool execution log methods
  async getToolExecutionLogs(userId: number): Promise<ToolExecutionLog[]> {
    return db
      .select()
      .from(toolExecutionLog)
      .where(eq(toolExecutionLog.userId, userId))
      .orderBy(desc(toolExecutionLog.executedAt));
  }

  async createToolExecutionLog(log: InsertToolExecutionLog): Promise<ToolExecutionLog> {
    const [newLog] = await db
      .insert(toolExecutionLog)
      .values(log)
      .returning();
    return newLog;
  }
  
  // User favorites methods
  async getUserFavorites(userId: number): Promise<UserFavorite[]> {
    return db
      .select()
      .from(userFavorites)
      .where(eq(userFavorites.userId, userId))
      .orderBy(desc(userFavorites.addedAt));
  }

  async addUserFavorite(favorite: InsertUserFavorite): Promise<UserFavorite> {
    const [newFavorite] = await db
      .insert(userFavorites)
      .values(favorite)
      .returning();
    return newFavorite;
  }

  async removeUserFavorite(userId: number, toolId: string): Promise<boolean> {
    const result = await db
      .delete(userFavorites)
      .where(
        and(
          eq(userFavorites.userId, userId),
          eq(userFavorites.toolId, toolId)
        )
      )
      .returning({ userId: userFavorites.userId });
    return result.length > 0;
  }
}

// Use the database storage implementation
export const storage = new DatabaseStorage();
