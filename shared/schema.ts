import { pgTable, text, serial, integer, boolean, timestamp, json, primaryKey, varchar } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Users table
export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  email: text("email").unique(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  lastLogin: timestamp("last_login"),
  role: text("role").default("user").notNull(),
});

// Tools table to store information about available security tools
export const tools = pgTable("tools", {
  id: serial("id").primaryKey(),
  toolId: text("tool_id").notNull().unique(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  category: text("category").notNull(),
  categoryLabel: text("category_label").notNull(),
  active: boolean("active").default(true).notNull(),
});

// Scan Results table to store port scan results
export const scanResults = pgTable("scan_results", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id),
  toolId: text("tool_id").notNull(),
  target: text("target").notNull(),
  scanTime: timestamp("scan_time").defaultNow().notNull(),
  results: json("results").notNull(),
  status: text("status").notNull(),
  duration: text("duration"),
});

// User Sessions table
export const sessions = pgTable("sessions", {
  id: text("id").primaryKey(),
  userId: integer("user_id").references(() => users.id),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  data: json("data"),
});

// Tool Execution Log table for audit and history
export const toolExecutionLog = pgTable("tool_execution_log", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id),
  toolId: text("tool_id").notNull(),
  executedAt: timestamp("executed_at").defaultNow().notNull(),
  parameters: json("parameters"),
  sourceIp: text("source_ip"),
  userAgent: text("user_agent"),
});

// User Favorites table
export const userFavorites = pgTable("user_favorites", {
  userId: integer("user_id").references(() => users.id).notNull(),
  toolId: text("tool_id").notNull(),
  addedAt: timestamp("added_at").defaultNow().notNull(),
  notes: text("notes"),
}, (t) => ({
  pk: primaryKey(t.userId, t.toolId),
}));

// Insert schemas
export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
  email: true,
  role: true,
});

export const insertToolSchema = createInsertSchema(tools).pick({
  toolId: true,
  name: true, 
  description: true,
  category: true,
  categoryLabel: true,
  active: true,
});

export const insertScanResultSchema = createInsertSchema(scanResults).pick({
  userId: true,
  toolId: true,
  target: true,
  results: true,
  status: true,
  duration: true,
});

export const insertSessionSchema = createInsertSchema(sessions).pick({
  id: true,
  userId: true,
  expiresAt: true,
  data: true,
});

export const insertToolExecutionLogSchema = createInsertSchema(toolExecutionLog).pick({
  userId: true,
  toolId: true,
  parameters: true,
  sourceIp: true,
  userAgent: true,
});

export const insertUserFavoriteSchema = createInsertSchema(userFavorites).pick({
  userId: true,
  toolId: true,
  notes: true,
});

// Export types
export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

export type InsertTool = z.infer<typeof insertToolSchema>;
export type Tool = typeof tools.$inferSelect;

export type InsertScanResult = z.infer<typeof insertScanResultSchema>;
export type ScanResult = typeof scanResults.$inferSelect;

export type InsertSession = z.infer<typeof insertSessionSchema>;
export type Session = typeof sessions.$inferSelect;

export type InsertToolExecutionLog = z.infer<typeof insertToolExecutionLogSchema>;
export type ToolExecutionLog = typeof toolExecutionLog.$inferSelect;

export type InsertUserFavorite = z.infer<typeof insertUserFavoriteSchema>;
export type UserFavorite = typeof userFavorites.$inferSelect;
