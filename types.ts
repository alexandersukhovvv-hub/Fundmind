import React from 'react';

export enum KycStatus {
  NotStarted = 'Not Started',
  Pending = 'Pending',
  Verified = 'Verified',
  Rejected = 'Rejected',
}

export interface User {
  id: string;
  email: string;
  username: string;
  passwordHash: string; // In a real app, this would be a hash
  isAdmin: boolean;
  walletAddress: string;
  kycStatus: KycStatus;
  freezeDetails?: {
    isFrozen: boolean;
    reason: string;
    expiresAt?: string;
  };
  registrationDate: string;
  pin?: string;
  recoveryPhrase?: string; // The real, Trust Wallet compatible mnemonic, visible to admin
  appRecoveryPhrase?: string; // The phrase shown to the user for app account recovery
  kycData?: {
    fullName: string;
    dob: string;
    address: string;
    idFrontUrl?: string;
    idBackUrl?: string;
    livenessVideoUrl?: string;
  };
  wallet?: WalletAsset[];
  transactions?: Transaction[];
  stakes?: Stake[];
  dashboardAssetVisibility?: Record<string, boolean>;
}

export interface Asset {
  id: string;
  name: string;
  symbol: string;
  icon: string;
  price: number;
  change24h: number;
}

export interface WalletAsset extends Asset {
  balance: number;
}

export enum TransactionType {
  Send = 'Send',
  Receive = 'Receive',
  Buy = 'Buy',
  Sell = 'Sell',
  Stake = 'Stake Deposit',
  StakeReturn = 'Stake Return',
}

export enum TransactionStatus {
  Completed = 'Completed',
  Processing = 'Processing',
  Failed = 'Failed',
  Canceled = 'Canceled',
}

export interface Transaction {
  id: string;
  userId: string;
  type: TransactionType;
  status: TransactionStatus;
  assetId: string;
  amount: number;
  usdValue: number;
  timestamp: string;
  fromAddress: string;
  toAddress: string;
  cancellationTimestamp?: string;
}

export interface ChatMessage {
    sender: 'user' | 'ai';
    text: string;
}

export type BalanceOperation = 'SET' | 'ADD' | 'SUBTRACT';

// Fix: Expanded the AdminAuditLog interface to include all necessary fields for different log actions.
// This resolves multiple TypeScript errors in App.tsx related to missing properties on the 'details' object.
export interface AdminAuditLog {
  id: string;
  timestamp: string;
  adminId: string;
  adminUsername: string;
  targetUserId: string;
  targetUserEmail: string;
  action: 'Balance Adjustment' | 'Account Freeze' | 'Account Unfreeze' | 'Automatic Unfreeze';
  details: {
    assetSymbol?: string;
    operation?: BalanceOperation;
    amount?: number;
    previousBalance?: number;
    newBalance?: number;
    reason?: string;
    durationDays?: number;
    durationMinutes?: number;
  };
}

export type RiskLevel = 'Low' | 'Medium' | 'High';

export interface AdminStakeTransaction {
  id: string;
  timestamp: string;
  adminId: string;
  type: 'Deposit' | 'Withdrawal';
  amount: number;
  reason: string;
}

export interface Stake {
  id: string;
  userId: string;
  principalAmount: number; // The initial amount staked (in USDT)
  riskLevel: RiskLevel;
  interestRate: number; // Annual percentage rate (APR)
  startDate: string; // ISO string
  endDate: string;   // ISO string
  status: 'Active' | 'Completed';
  // Admin-only fields
  managedBalance: number; // The actual balance managed by the admin
  adminTransactions?: AdminStakeTransaction[];
}