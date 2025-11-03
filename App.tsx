import React, { useState, useEffect, useRef, createContext, useContext, useCallback, useMemo } from 'react';
import ReactDOM from 'react-dom';
import { ethers } from 'ethers';
import { getAiResponse } from './services/geminiService';
import { 
    User, Asset, WalletAsset, Transaction, ChatMessage, AdminAuditLog, BalanceOperation, Stake, RiskLevel,
    KycStatus, TransactionType, TransactionStatus 
} from './types';
import {
    DashboardIcon, TransactionsIcon, ProfileIcon, AdminIcon, ExitAdminIcon, LogoutIcon,
    SendIcon, ReceiveIcon, BuyIcon, SellIcon, CloseIcon, CardIcon, Spinner, AnalyticsIcon, BalanceIcon,
    GenericAssetIcon, ChevronDoubleLeftIcon, ChevronDoubleRightIcon, LockIcon, EmailIcon,
    ChevronDoubleUpIcon, ChevronDoubleDownIcon, ChatIcon, KycIcon, CameraIcon, KeyIcon, EyeIcon, CoinsIcon,
    ChartBarIcon, InformationCircleIcon, ArrowUpIcon, ArrowDownIcon, InvestIcon, SwapIcon, ArrowPathIcon
} from './components/Icons';

// --- MOCK DATA & HELPERS ---

const PREDEFINED_MNEMONICS = [
    // 0: Admin Wallet (1A)
    'Enemy Mechanic winner rescue artwork office idea witness couch river tribe rare',
    // 1: First User Wallet (2A)
    'vocal man caution beauty skin end fork fade soup call rookie slam',
    // 2: User Wallet (3A)
    'galaxy orbit rocket lunar solar nebula gravity cosmos star planet comet asteroid',
    // 3: User Wallet (4A)
    'umbra zenith nova quasar vector binary cluster field fusion gamma helix ion',
    // 4: User Wallet (5A)
    'jet kappa light magnet node omega phase quantum radian singularity tensor ultra',
    // 5: User Wallet (6A)
    'vacuum wormhole xylon year zetta alpha beta delta echo flux giga',
    // 6: User Wallet (7A)
    'clutch success shrug hire timber firm survey brisk polar panther oyster bitter',
    // 7: User Wallet (8A)
    'fringe cigar impose canvas protest jealous lucky express certain illegal horror lumber',
    // 8: User Wallet (9A)
    'average sweet wagon tragic problem hero apple table vicious renew solid humble',
    // 9: User Wallet (10A)
    'ripple junk hammer pulp special ketchup pair install ship deputy thrive leader',
    // 10: User Wallet (11A)
    'devote army mouse owner venue choice sniff meat guard total absorb thank',
];

const APP_RECOVERY_WORD_LIST = [
    'ocean', 'dream', 'future', 'spirit', 'journey', 'quest', 'valor', 'truth', 'honor', 'wisdom',
    'beacon', 'harbor', 'oasis', 'haven', 'sanctuary', 'zenith', 'apex', 'summit', 'pinnacle', 'crest',
    'echo', 'nexus', 'matrix', 'cypher', 'script', 'token', 'ledger', 'shard', 'node', 'oracle',
    'aurora', 'nebula', 'cosmos', 'galaxy', 'quasar', 'nova', 'pulse', 'spark', 'flare', 'beam',
    'anchor', 'keystone', 'pillar', 'foundation', 'cornerstone', 'guide', 'mentor', 'ally', 'shield', 'guard'
];


const defaultAssets: Asset[] = [
  { id: 'bitcoin', name: 'Bitcoin', symbol: 'BTC', icon: '', price: 0, change24h: 0 },
  { id: 'ethereum', name: 'Ethereum', symbol: 'ETH', icon: '', price: 0, change24h: 0 },
  { id: 'tether', name: 'Tether', symbol: 'USDT', icon: '', price: 0, change24h: 0 },
  { id: 'binancecoin', name: 'BNB', symbol: 'BNB', icon: '', price: 0, change24h: 0 },
];

const formatCurrency = (value: number) => `$${value.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
const formatLargeNumber = (value: number) => {
    if (value >= 1_000_000_000) return `$${(value / 1_000_000_000).toFixed(2)}B`;
    if (value >= 1_000_000) return `$${(value / 1_000_000).toFixed(2)}M`;
    // Fix: Added 'en-US' locale to `toLocaleString` to ensure consistent number formatting and resolve potential errors.
    return `$${value.toLocaleString('en-US')}`;
};
const formatCrypto = (value: number, symbol?: string) => `${value.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 6 })}${symbol ? ` ${symbol}` : ''}`;
const formatPercent = (value: number | null | undefined) => {
    if (value === null || value === undefined || isNaN(value)) {
        return '0.00%';
    }
    return `${value.toFixed(2)}%`;
};
const fileToBase64 = (file: File): Promise<string> => new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = error => reject(error);
});

const RISK_LEVELS: Record<RiskLevel, { apr: number; color: string }> = {
    'Low': { apr: 0.25, color: 'text-accent-primary' },
    'Medium': { apr: 0.45, color: 'text-accent-warning' },
    'High': { apr: 0.85, color: 'text-accent-negative' },
};

const ASSET_NETWORKS: Record<string, { name: string; standard: string }[]> = {
    'bitcoin': [{ name: 'Bitcoin Network', standard: 'BTC' }],
    'ethereum': [{ name: 'Ethereum', standard: 'ERC20' }],
    'tether': [
        { name: 'Ethereum', standard: 'ERC20' },
        { name: 'BNB Smart Chain', standard: 'BEP20' }
    ],
    'binancecoin': [{ name: 'BNB Smart Chain', standard: 'BEP20' }],
};

// Blockchain interaction constants
const ETH_RPC_URL = 'https://rpc.ankr.com/eth';
const BNB_RPC_URL = 'https://rpc.ankr.com/bsc';
const USDT_ERC20_CONTRACT = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
const USDT_BEP20_CONTRACT = '0x55d398326f99059fF775485246999027B3197955';
const TOKEN_ABI = [
    "function balanceOf(address owner) view returns (uint256)",
    "function decimals() view returns (uint8)"
];


// --- AUTH CONTEXT ---
interface AuthContextType {
    currentUser: User | null;
    users: User[];
    availableAssets: Asset[];
    adminAuditLog: AdminAuditLog[];
    stakes: Stake[];
    justLoggedIn: boolean;
    rememberedUserEmail: string | null;
    adminPanelPassword: string;
    isCreatingWallet: boolean;
    login: (email: string, password: string, rememberMe: boolean) => boolean;
    loginWithPin: (pin: string) => boolean;
    logout: () => void;
    register: (email: string, username: string, password: string) => boolean;
    updateUser: (updatedUser: User) => void;
    addTransaction: (userId: string, transaction: Omit<Transaction, 'id' | 'userId' | 'timestamp'>) => void;
    adjustUserBalance: (targetUserId: string, assetId: string, operation: BalanceOperation, amount: number, reason: string) => boolean;
    updateAdminPanelPassword: (currentPassword: string, newPassword: string) => { success: boolean; message: string };
    updateAdminWalletMnemonic: (newMnemonic: string, adminPanelPasswordForVerification: string) => { success: boolean; message: string };
    setJustLoggedIn: (status: boolean) => void;
    setUserPin: (pin: string) => void;
    clearRememberedUser: () => void;
    updateUserCredentials: (
        type: 'email' | 'password' | 'pin' | 'username',
        currentPasswordForVerification: string,
        newValue: string
    ) => { success: boolean; message: string };
    recoverAccount: (phrase: string, newPassword: string) => { success: boolean; message: string };
    addAsset: (asset: Omit<Asset, 'price' | 'change24h'>) => { success: boolean, message: string };
    updateAsset: (asset: Asset) => { success: boolean, message: string };
    deleteAsset: (assetId: string) => { success: boolean, message: string };
    freezeUser: (targetUserId: string, reason: string, durationDays?: number, durationMinutes?: number) => { success: boolean; message: string };
    unfreezeUser: (targetUserId: string) => { success: boolean; message: string };
    createStake: (userId: string, amount: number, periodMonths: number, riskLevel: RiskLevel) => { success: boolean, message: string };
    manageStakeFunds: (stakeId: string, type: 'Deposit' | 'Withdrawal', amount: number, reason: string) => { success: boolean; message: string };
    completeWalletCreation: () => void;
}
const AuthContext = createContext<AuthContextType | null>(null);
const useAuth = () => useContext(AuthContext)!;

const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [availableAssets, setAvailableAssets] = useState<Asset[]>(() => {
        const savedAssets = localStorage.getItem('fundmind_assets');
        return savedAssets ? JSON.parse(savedAssets) : defaultAssets;
    });

    const [users, setUsers] = useState<User[]>(() => {
        const savedUsers = localStorage.getItem('fundmind_users');
        if (savedUsers) return JSON.parse(savedUsers);

        // Deriving wallet info from mnemonics
        const adminWallet = ethers.Wallet.fromPhrase(PREDEFINED_MNEMONICS[0]);
        const user2AWallet = ethers.Wallet.fromPhrase(PREDEFINED_MNEMONICS[1]);

        return [
            {
                id: 'admin-user',
                email: 'admin@fundmind.app',
                username: 'Admin',
                passwordHash: '73839292729',
                isAdmin: true,
                walletAddress: adminWallet.address,
                kycStatus: KycStatus.Verified,
                freezeDetails: { isFrozen: false, reason: '' },
                registrationDate: new Date().toISOString(),
                wallet: defaultAssets.map(a => ({ ...a, balance: a.symbol === 'USDT' ? 10000 : 5 })),
                transactions: [],
                stakes: [],
                recoveryPhrase: PREDEFINED_MNEMONICS[0],
                appRecoveryPhrase: 'honor wisdom beacon harbor oasis haven sanctuary zenith apex summit pinnacle crest',
            },
            {
                id: 'user-2A',
                email: 'user@fundmind.app',
                username: 'User2A',
                passwordHash: 'password123',
                isAdmin: false,
                walletAddress: user2AWallet.address,
                kycStatus: KycStatus.NotStarted,
                freezeDetails: { isFrozen: false, reason: '' },
                registrationDate: new Date().toISOString(),
                wallet: defaultAssets.map(a => ({ ...a, balance: a.symbol === 'USDT' ? 500 : 0.5 })),
                transactions: [],
                stakes: [],
                recoveryPhrase: PREDEFINED_MNEMONICS[1],
                appRecoveryPhrase: 'echo nexus matrix cypher script token ledger shard node oracle aurora nebula',
            }
        ];
    });

    const [stakes, setStakes] = useState<Stake[]>(() => {
        const savedStakes = localStorage.getItem('fundmind_stakes');
        return savedStakes ? JSON.parse(savedStakes) : [];
    });

    const [currentUser, setCurrentUser] = useState<User | null>(() => {
        const savedUser = localStorage.getItem('fundmind_currentUser');
        return savedUser ? JSON.parse(savedUser) : null;
    });
    
    const [justLoggedIn, setJustLoggedIn] = useState(false);
    const [isCreatingWallet, setIsCreatingWallet] = useState(false);


    const [rememberedUserEmail, setRememberedUserEmail] = useState<string | null>(() => {
        return localStorage.getItem('fundmind_remembered_email');
    });

    const [adminAuditLog, setAdminAuditLog] = useState<AdminAuditLog[]>(() => {
        const savedLog = localStorage.getItem('fundmind_admin_audit_log');
        return savedLog ? JSON.parse(savedLog) : [];
    });

    const [adminPanelPassword, setAdminPanelPassword] = useState<string>(() => {
        const savedPass = localStorage.getItem('fundmind_admin_panel_password');
        return savedPass || 'ErC20admin!@-/76';
    });

    useEffect(() => {
        localStorage.setItem('fundmind_assets', JSON.stringify(availableAssets));
    }, [availableAssets]);

    useEffect(() => {
        try {
            const usersToStore = users.map(user => {
                // To prevent localStorage quota errors, we only store KYC image/video data
                // for users whose applications are actively pending review.
                if (user.kycData && user.kycStatus !== KycStatus.Pending) {
                    const { idFrontUrl, idBackUrl, livenessVideoUrl, ...restOfKycData } = user.kycData;
                    // Create a new object to avoid modifying the in-memory state
                    const sanitizedUser = { ...user, kycData: restOfKycData };
                    return sanitizedUser;
                }
                return user; // For pending users, store the full data.
            });
            localStorage.setItem('fundmind_users', JSON.stringify(usersToStore));
        } catch (error) {
            console.error("Error writing users to localStorage:", error);
        }
    }, [users]);

    useEffect(() => {
        localStorage.setItem('fundmind_stakes', JSON.stringify(stakes));
    }, [stakes]);
    
    useEffect(() => {
        localStorage.setItem('fundmind_admin_audit_log', JSON.stringify(adminAuditLog));
    }, [adminAuditLog]);

    useEffect(() => {
        try {
            if (currentUser) {
                // Sanitize current user data before saving to avoid quota errors
                const userToStore = { ...currentUser };
                if (userToStore.kycData && userToStore.kycStatus !== KycStatus.Pending) {
                    const { idFrontUrl, idBackUrl, livenessVideoUrl, ...restOfKycData } = userToStore.kycData;
                    userToStore.kycData = restOfKycData as any;
                }
                localStorage.setItem('fundmind_currentUser', JSON.stringify(userToStore));
            } else {
                localStorage.removeItem('fundmind_currentUser');
            }
        } catch (error) {
            console.error("Error writing currentUser to localStorage:", error);
        }
    }, [currentUser]);

    useEffect(() => {
        localStorage.setItem('fundmind_admin_panel_password', adminPanelPassword);
    }, [adminPanelPassword]);

    const updateUser = useCallback((updatedUser: User) => {
        setUsers(prevUsers => prevUsers.map(u => u.id === updatedUser.id ? updatedUser : u));
        setCurrentUser(prevUser => {
            if (prevUser?.id === updatedUser.id) {
                return updatedUser;
            }
            return prevUser;
        });
    }, []);

    const addTransaction = useCallback((userId: string, transactionData: Omit<Transaction, 'id' | 'userId' | 'timestamp'>) => {
        const newTransaction: Transaction = {
            ...transactionData,
            id: `txn-${Date.now()}`,
            userId,
            timestamp: new Date().toISOString(),
        };
    
        const updateUserState = (user: User) => {
            const updatedTransactions = [...(user.transactions || []), newTransaction];
            let updatedWallet = user.wallet ? [...user.wallet] : availableAssets.map(a => ({ ...a, balance: 0 }));
            const assetIndex = updatedWallet.findIndex(a => a.id === transactionData.assetId);
    
            if (assetIndex > -1) {
                const currentAsset = updatedWallet[assetIndex];
                let newBalance = currentAsset.balance;
                switch (transactionData.type) {
                    case TransactionType.Send:
                    case TransactionType.Sell:
                    case TransactionType.Stake:
                        newBalance -= transactionData.amount;
                        break;
                    case TransactionType.Receive:
                    case TransactionType.Buy:
                    case TransactionType.StakeReturn:
                        newBalance += transactionData.amount;
                        break;
                }
                updatedWallet[assetIndex] = { ...currentAsset, balance: newBalance };
            } else if (transactionData.type === TransactionType.Buy || transactionData.type === TransactionType.Receive || transactionData.type === TransactionType.StakeReturn) {
                 const newAsset = availableAssets.find(a => a.id === transactionData.assetId);
                 if (newAsset) updatedWallet.push({ ...newAsset, balance: transactionData.amount });
            }
            return { ...user, transactions: updatedTransactions, wallet: updatedWallet };
        };
        
        setUsers(prevUsers => prevUsers.map(user => user.id === userId ? updateUserState(user) : user));
        
        setCurrentUser(prevUser => {
            if (prevUser && prevUser.id === userId) {
                return updateUserState(prevUser);
            }
            return prevUser;
        });
    }, [availableAssets]);

    // Effect for automatically unfreezing accounts
    useEffect(() => {
        const intervalId = setInterval(() => {
            setUsers(prevUsers => {
                const now = new Date();
                let usersWereUpdated = false;
                const newLogs: AdminAuditLog[] = [];
    
                const updatedUsers = prevUsers.map(user => {
                    if (user.freezeDetails?.isFrozen && user.freezeDetails.expiresAt) {
                        if (now >= new Date(user.freezeDetails.expiresAt)) {
                            usersWereUpdated = true;
                            newLogs.push({
                                id: `log-${Date.now()}-${user.id}`,
                                timestamp: new Date().toISOString(),
                                adminId: 'SYSTEM',
                                adminUsername: 'System',
                                targetUserId: user.id,
                                targetUserEmail: user.email,
                                action: 'Automatic Unfreeze',
                                details: { reason: 'Freeze duration expired.' },
                            });
                            return {
                                ...user,
                                freezeDetails: { isFrozen: false, reason: '', expiresAt: undefined }
                            };
                        }
                    }
                    return user;
                });
    
                if (usersWereUpdated) {
                    setAdminAuditLog(prevLogs => [...newLogs, ...prevLogs]);
                    return updatedUsers;
                }
    
                return prevUsers;
            });
        }, 60000); // Check every minute
    
        return () => clearInterval(intervalId);
    }, []);

    // Effect for automatically cancelling 'processing' transactions after their expiry
    useEffect(() => {
        const transactionCheckInterval = setInterval(() => {
            const now = new Date();
            let wasUpdated = false;

            const updatedUsers = users.map(user => {
                if (!user.transactions || user.transactions.length === 0) {
                    return user;
                }

                let userWasUpdated = false;
                const newTransactions = user.transactions.map(tx => {
                    if (tx.status === TransactionStatus.Processing && tx.cancellationTimestamp && now >= new Date(tx.cancellationTimestamp)) {
                        wasUpdated = true;
                        userWasUpdated = true;
                        return { ...tx, status: TransactionStatus.Canceled };
                    }
                    return tx;
                });

                if (userWasUpdated) {
                    return { ...user, transactions: newTransactions };
                }
                return user;
            });

            if (wasUpdated) {
                setUsers(updatedUsers);
            }
        }, 30000); // Check every 30 seconds

        return () => clearInterval(transactionCheckInterval);
    }, [users]);

    // Effect for handling expired stakes
    useEffect(() => {
        const stakeCheckInterval = setInterval(() => {
            const now = new Date();
            const completedStakeIds: string[] = [];
            
            stakes.forEach(stake => {
                if (stake.status === 'Active' && now >= new Date(stake.endDate)) {
                    completedStakeIds.push(stake.id);
                }
            });

            if (completedStakeIds.length > 0) {
                setStakes(prevStakes => prevStakes.map(s => completedStakeIds.includes(s.id) ? { ...s, status: 'Completed' } : s));
                
                setUsers(prevUsers => prevUsers.map(user => {
                    const userStakesToComplete = stakes.filter(s => s.userId === user.id && completedStakeIds.includes(s.id));
                    if (userStakesToComplete.length === 0) return user;

                    let updatedUser = { ...user };
                    let totalReturn = 0;

                    userStakesToComplete.forEach(stake => {
                        const durationInYears = (new Date(stake.endDate).getTime() - new Date(stake.startDate).getTime()) / (1000 * 60 * 60 * 24 * 365.25);
                        const interest = stake.principalAmount * stake.interestRate * durationInYears;
                        const payout = stake.principalAmount + interest;
                        totalReturn += payout;

                        addTransaction(user.id, {
                            type: TransactionType.StakeReturn,
                            status: TransactionStatus.Completed,
                            assetId: 'tether',
                            amount: payout,
                            usdValue: payout,
                            fromAddress: 'staking-contract',
                            toAddress: user.walletAddress
                        });
                    });
                    return updatedUser;
                }));
            }
        }, 60000); // Check every minute

        return () => clearInterval(stakeCheckInterval);
    }, [stakes, addTransaction, users]);


    const login = (email: string, password: string, rememberMe: boolean): boolean => {
        const user = users.find(u => u.email === email && u.passwordHash === password);
        if (user) {
            setCurrentUser(user);
            setJustLoggedIn(true);
            if (rememberMe) {
                localStorage.setItem('fundmind_remembered_email', email);
                setRememberedUserEmail(email);
            } else {
                localStorage.removeItem('fundmind_remembered_email');
                setRememberedUserEmail(null);
            }
            return true;
        }
        return false;
    };

    const loginWithPin = (pin: string): boolean => {
        if (!rememberedUserEmail) return false;
        const user = users.find(u => u.email === rememberedUserEmail);
        if (user && user.pin === pin) {
            setCurrentUser(user);
            setJustLoggedIn(true);
            return true;
        }
        return false;
    };
    
    const clearRememberedUser = () => {
        localStorage.removeItem('fundmind_remembered_email');
        setRememberedUserEmail(null);
    };
    
    const logout = () => setCurrentUser(null);
    
    const register = (email: string, username: string, password: string): boolean => {
        if (users.some(u => u.email === email)) return false;

        // 1. Generate the real, Trust-Wallet compatible wallet and phrase
        const newWallet = ethers.Wallet.createRandom();
        const realRecoveryPhrase = newWallet.mnemonic.phrase;
        const walletAddress = newWallet.address;

        // 2. Generate a separate, simple phrase for app recovery
        const appRecoveryPhrase = Array.from({ length: 12 }, () => APP_RECOVERY_WORD_LIST[Math.floor(Math.random() * APP_RECOVERY_WORD_LIST.length)]).join(' ');

        const newUser: User = {
            id: `user-${Date.now()}`,
            email,
            username,
            passwordHash: password,
            isAdmin: false,
            walletAddress,
            kycStatus: KycStatus.NotStarted,
            freezeDetails: { isFrozen: false, reason: '' },
            registrationDate: new Date().toISOString(),
            recoveryPhrase: realRecoveryPhrase, // The real one for the admin
            appRecoveryPhrase: appRecoveryPhrase, // The one shown to the user
            wallet: defaultAssets.map(a => ({ ...a, balance: 0 })),
            transactions: [],
            stakes: [],
        };
        setUsers(prev => [...prev, newUser]);
        setCurrentUser(newUser);
        setIsCreatingWallet(true);
        return true;
    };

    const completeWalletCreation = () => {
        setIsCreatingWallet(false);
        setJustLoggedIn(true);
    };
    
    const adjustUserBalance = (targetUserId: string, assetId: string, operation: BalanceOperation, amount: number, reason: string): boolean => {
        if (!currentUser || !currentUser.isAdmin) return false;

        const targetUser = users.find(u => u.id === targetUserId);
        const assetTemplate = availableAssets.find(a => a.id === assetId);
        if (!targetUser || !assetTemplate) return false;

        let userWallet = targetUser.wallet ? [...targetUser.wallet] : availableAssets.map(a => ({ ...a, balance: 0 }));
        const assetIndex = userWallet.findIndex(a => a.id === assetId);
        
        const previousBalance = assetIndex > -1 ? userWallet[assetIndex].balance : 0;
        let newBalance = previousBalance;

        switch (operation) {
            case 'SET': newBalance = amount; break;
            case 'ADD': newBalance += amount; break;
            case 'SUBTRACT': newBalance -= amount; break;
        }

        if (newBalance < 0) newBalance = 0;

        if (assetIndex > -1) {
            userWallet[assetIndex] = { ...userWallet[assetIndex], balance: newBalance };
        } else {
            userWallet.push({ ...assetTemplate, balance: newBalance });
        }
        
        const updatedUser = { ...targetUser, wallet: userWallet };
        updateUser(updatedUser);

        const logEntry: AdminAuditLog = {
            id: `log-${Date.now()}`,
            timestamp: new Date().toISOString(),
            adminId: currentUser.id,
            adminUsername: currentUser.username,
            targetUserId: targetUser.id,
            targetUserEmail: targetUser.email,
            action: 'Balance Adjustment',
            details: { assetSymbol: assetTemplate.symbol, operation, amount, previousBalance, newBalance, reason },
        };
        setAdminAuditLog(prev => [logEntry, ...prev]);

        return true;
    };

    const unfreezeUser = (targetUserId: string): { success: boolean; message: string } => {
        if (!currentUser || !currentUser.isAdmin) {
            return { success: false, message: "Permission denied." };
        }
        const targetUser = users.find(u => u.id === targetUserId);
        if (!targetUser) {
            return { success: false, message: "User not found." };
        }

        const updatedUser: User = {
            ...targetUser,
            freezeDetails: { isFrozen: false, reason: '', expiresAt: undefined }
        };

        const logEntry: AdminAuditLog = {
            id: `log-${Date.now()}`,
            timestamp: new Date().toISOString(),
            adminId: currentUser.id,
            adminUsername: currentUser.username,
            targetUserId: targetUser.id,
            targetUserEmail: targetUser.email,
            action: 'Account Unfreeze',
            details: { reason: 'Admin unfreeze action' },
        };

        updateUser(updatedUser);
        setAdminAuditLog(prev => [logEntry, ...prev]);

        return { success: true, message: `User account for ${targetUser.username} has been unfrozen.` };
    };

    const freezeUser = (targetUserId: string, reason: string, durationDays?: number, durationMinutes?: number): { success: boolean; message: string } => {
        if (!currentUser || !currentUser.isAdmin) {
            return { success: false, message: "Permission denied." };
        }
        const targetUser = users.find(u => u.id === targetUserId);
        if (!targetUser) {
            return { success: false, message: "User not found." };
        }
        if (!reason) {
            return { success: false, message: "A reason is required to freeze an account." };
        }

        let expiresAt: string | undefined = undefined;
        if ((durationDays && durationDays > 0) || (durationMinutes && durationMinutes > 0)) {
            const expiryDate = new Date();
            if (durationDays && durationDays > 0) {
                expiryDate.setDate(expiryDate.getDate() + durationDays);
            }
            if (durationMinutes && durationMinutes > 0) {
                expiryDate.setMinutes(expiryDate.getMinutes() + durationMinutes);
            }
            expiresAt = expiryDate.toISOString();
        }
        
        const updatedUser: User = {
            ...targetUser,
            freezeDetails: { isFrozen: true, reason, expiresAt }
        };
        const logEntry: AdminAuditLog = {
            id: `log-${Date.now()}`,
            timestamp: new Date().toISOString(),
            adminId: currentUser.id,
            adminUsername: currentUser.username,
            targetUserId: targetUser.id,
            targetUserEmail: targetUser.email,
            action: 'Account Freeze',
            details: { reason, durationDays, durationMinutes },
        };

        updateUser(updatedUser);
        setAdminAuditLog(prev => [logEntry, ...prev]);

        return { success: true, message: `User account for ${targetUser.username} has been frozen.` };
    };
    
    const updateAdminPanelPassword = (currentPassword: string, newPassword: string): { success: boolean; message: string } => {
        if (currentPassword !== adminPanelPassword) {
            return { success: false, message: "Incorrect current admin panel password." };
        }
        if (!newPassword) {
            return { success: false, message: "New password cannot be empty." };
        }
        setAdminPanelPassword(newPassword);
        return { success: true, message: "Admin Panel password updated successfully." };
    };

    const updateAdminWalletMnemonic = (newMnemonic: string, adminPanelPasswordForVerification: string): { success: boolean; message: string } => {
        if (adminPanelPasswordForVerification !== adminPanelPassword) {
            return { success: false, message: "Incorrect admin panel password." };
        }

        let newWallet;
        try {
            newWallet = ethers.Wallet.fromPhrase(newMnemonic.trim());
        } catch (error) {
            return { success: false, message: "Invalid mnemonic phrase. Please check the 12 words." };
        }

        const adminUser = users.find(u => u.isAdmin);
        if (!adminUser) {
            return { success: false, message: "Admin user account not found." };
        }

        const updatedAdminUser: User = {
            ...adminUser,
            walletAddress: newWallet.address,
            recoveryPhrase: newMnemonic.trim(),
        };

        updateUser(updatedAdminUser); // This updates both 'users' and 'currentUser' state
        return { success: true, message: "Admin wallet updated successfully." };
    };

    const updateUserCredentials = (type: 'email' | 'password' | 'pin' | 'username', currentPasswordForVerification: string, newValue: string): { success: boolean; message: string } => {
        if (!currentUser) return { success: false, message: "No user is logged in." };
    
        const user = users.find(u => u.id === currentUser.id);
        if (!user) return { success: false, message: "Could not find user data." };
    
        if (user.passwordHash !== currentPasswordForVerification) {
            return { success: false, message: "Incorrect password." };
        }

        if (type === 'email' && users.some(u => u.email === newValue && u.id !== currentUser.id)) {
            return { success: false, message: "This email address is already in use." };
        }

        if (type === 'username' && users.some(u => u.username.toLowerCase() === newValue.toLowerCase() && u.id !== currentUser.id)) {
            return { success: false, message: "This nickname is already taken." };
        }
    
        let updatedUser = { ...user };
        switch (type) {
            case 'email':
                updatedUser.email = newValue;
                break;
            case 'password':
                updatedUser.passwordHash = newValue;
                break;
            case 'pin':
                updatedUser.pin = newValue;
                break;
            case 'username':
                updatedUser.username = newValue;
                break;
        }
    
        updateUser(updatedUser);
        return { success: true, message: `${type.charAt(0).toUpperCase() + type.slice(1)} updated successfully.` };
    };
    
    const setUserPin = (pin: string) => {
        if (!currentUser) return;
        const updatedUser = { ...currentUser, pin };
        updateUser(updatedUser);
    };

    const recoverAccount = (phrase: string, newPassword: string): { success: boolean; message: string } => {
        const user = users.find(u => u.appRecoveryPhrase === phrase.trim());
        if (!user) {
            return { success: false, message: "Invalid account recovery phrase." };
        }
        
        const updatedUser = { ...user, passwordHash: newPassword };
        updateUser(updatedUser);
        
        setCurrentUser(updatedUser);
        setJustLoggedIn(true);
        localStorage.setItem('fundmind_remembered_email', updatedUser.email);
        setRememberedUserEmail(updatedUser.email);

        return { success: true, message: "Password updated successfully." };
    };

    const addAsset = (asset: Omit<Asset, 'price' | 'change24h'>) => {
        if (availableAssets.some(a => a.id === asset.id || a.symbol.toLowerCase() === asset.symbol.toLowerCase())) {
            return { success: false, message: "Asset with this CoinGecko ID or Symbol already exists." };
        }
        const newAsset: Asset = { ...asset, price: 0, change24h: 0 };
        setAvailableAssets(prev => [...prev, newAsset]);
        return { success: true, message: "Asset added successfully." };
    };
    
    const updateAsset = (updatedAsset: Asset) => {
        if (availableAssets.some(a => a.id !== updatedAsset.id && a.symbol.toLowerCase() === updatedAsset.symbol.toLowerCase())) {
            return { success: false, message: "Another asset with this symbol already exists." };
        }
        setAvailableAssets(prev => prev.map(a => a.id === updatedAsset.id ? { ...a, ...updatedAsset } : a));
        return { success: true, message: "Asset updated successfully." };
    };
    
    const deleteAsset = (assetId: string) => {
        setAvailableAssets(prev => prev.filter(a => a.id !== assetId));
        return { success: true, message: "Asset deleted successfully." };
    };

    const createStake = (userId: string, amount: number, periodMonths: number, riskLevel: RiskLevel): { success: boolean; message: string } => {
        const user = users.find(u => u.id === userId);
        if (!user) return { success: false, message: "User not found." };

        const usdtBalance = user.wallet?.find(a => a.symbol === 'USDT')?.balance || 0;
        if (amount > usdtBalance) return { success: false, message: "Insufficient USDT balance." };

        addTransaction(userId, {
            type: TransactionType.Stake,
            status: TransactionStatus.Completed,
            assetId: 'tether',
            amount,
            usdValue: amount,
            fromAddress: user.walletAddress,
            toAddress: 'staking-contract'
        });

        const startDate = new Date();
        const endDate = new Date(startDate);
        endDate.setMonth(startDate.getMonth() + periodMonths);

        const newStake: Stake = {
            id: `stake-${Date.now()}`,
            userId,
            principalAmount: amount,
            riskLevel,
            interestRate: RISK_LEVELS[riskLevel].apr,
            startDate: startDate.toISOString(),
            endDate: endDate.toISOString(),
            status: 'Active',
            managedBalance: amount, // Admin starts with the principal
            adminTransactions: [],
        };
        
        setStakes(prev => [...prev, newStake]);
        return { success: true, message: "Stake created successfully!" };
    };

    const manageStakeFunds = (stakeId: string, type: 'Deposit' | 'Withdrawal', amount: number, reason: string) => {
        if (!currentUser || !currentUser.isAdmin) return { success: false, message: "Permission denied." };
        
        const stakeIndex = stakes.findIndex(s => s.id === stakeId);
        if (stakeIndex === -1) return { success: false, message: "Stake not found." };
        
        const stake = stakes[stakeIndex];
        const user = users.find(u => u.id === stake.userId);
        if (!user) return { success: false, message: "User associated with stake not found." };
    
        const now = new Date();
        const endDate = new Date(stake.endDate);
        const hoursLeft = (endDate.getTime() - now.getTime()) / (1000 * 60 * 60);
    
        if (hoursLeft <= 24) {
            return { success: false, message: "Fund management is locked 24 hours before stake expiration." };
        }
    
        let newManagedBalance: number;
        let updatedUserWallet = [...(user.wallet || [])];
        const usdtAssetTemplate = availableAssets.find(a => a.id === 'tether');
        if (!usdtAssetTemplate) return { success: false, message: "USDT asset configuration not found." };
    
        const usdtWalletAssetIndex = updatedUserWallet.findIndex(a => a.id === 'tether');
        let usdtWalletAsset = usdtWalletAssetIndex > -1 ? updatedUserWallet[usdtWalletAssetIndex] : null;
    
        if (type === 'Deposit') { // Top up client's staking (deduct from their balance)
            if (!usdtWalletAsset || usdtWalletAsset.balance < amount) {
                return { success: false, message: "Client has insufficient USDT balance for this top up." };
            }
            
            // Deduct from user's main wallet
            usdtWalletAsset.balance -= amount;
            updatedUserWallet[usdtWalletAssetIndex] = usdtWalletAsset;
    
            // Add to stake's managed balance
            newManagedBalance = stake.managedBalance + amount;
        } else { // Withdrawal from client's staking (transfer to their balance)
            if (amount > stake.managedBalance) {
                return { success: false, message: "Withdrawal amount cannot exceed the stake's managed balance." };
            }
    
            // Add to user's main wallet
            if (usdtWalletAsset) {
                usdtWalletAsset.balance += amount;
                updatedUserWallet[usdtWalletAssetIndex] = usdtWalletAsset;
            } else {
                // User doesn't have USDT in their wallet, add it.
                updatedUserWallet.push({ ...usdtAssetTemplate, balance: amount });
            }
    
            // Deduct from stake's managed balance
            newManagedBalance = stake.managedBalance - amount;
        }
    
        // Update user state
        const updatedUser = { ...user, wallet: updatedUserWallet };
        updateUser(updatedUser);
    
        // Update stake state
        const updatedStake: Stake = {
            ...stake,
            managedBalance: newManagedBalance,
            adminTransactions: [
                ...(stake.adminTransactions || []),
                {
                    id: `adm-tx-${Date.now()}`,
                    timestamp: new Date().toISOString(),
                    adminId: currentUser.id,
                    type,
                    amount,
                    reason,
                },
            ],
        };
    
        setStakes(prev => prev.map(s => s.id === stakeId ? updatedStake : s));
        return { success: true, message: `Successfully performed ${type} of ${formatCurrency(amount)}.` };
    };

    return (
        <AuthContext.Provider value={{ currentUser, users, availableAssets, adminAuditLog, stakes, login, logout, register, updateUser, addTransaction, adjustUserBalance, updateAdminPanelPassword, updateAdminWalletMnemonic, justLoggedIn, setJustLoggedIn, setUserPin, rememberedUserEmail, loginWithPin, clearRememberedUser, updateUserCredentials, adminPanelPassword, recoverAccount, addAsset, updateAsset, deleteAsset, freezeUser, unfreezeUser, createStake, manageStakeFunds, isCreatingWallet, completeWalletCreation }}>
            {children}
        </AuthContext.Provider>
    );
};

// --- API DATA FETCHER ---
const useAssetData = (currentUser: User | null, addTransaction: AuthContextType['addTransaction']) => {
    const { availableAssets, updateUser } = useAuth();
    const [assets, setAssets] = useState<Asset[]>(availableAssets);
    const [walletAssets, setWalletAssets] = useState<WalletAsset[]>([]);
    const [totalValue, setTotalValue] = useState(0);
    const [isLoading, setIsLoading] = useState(true);
    const [realBalances, setRealBalances] = useState<Record<string, number>>({});
    const addTransactionRef = useRef(addTransaction);
    const updateUserRef = useRef(updateUser);
    const pollingRef = useRef<NodeJS.Timeout | null>(null);


    useEffect(() => {
        addTransactionRef.current = addTransaction;
        updateUserRef.current = updateUser;
    }, [addTransaction, updateUser]);

    useEffect(() => {
        const fetchRealBalances = async (address: string) => {
            const ethProvider = new ethers.JsonRpcProvider(ETH_RPC_URL);
            const bnbProvider = new ethers.JsonRpcProvider(BNB_RPC_URL);
            const usdtErc20 = new ethers.Contract(USDT_ERC20_CONTRACT, TOKEN_ABI, ethProvider);
            const usdtBep20 = new ethers.Contract(USDT_BEP20_CONTRACT, TOKEN_ABI, bnbProvider);

            try {
                const [ btcResponse, ethBalance, bnbBalance, usdtErc20Balance, usdtBep20Balance ] = await Promise.all([
                    fetch(`https://cors-anywhere.herokuapp.com/https://blockchain.info/q/addressbalance/${address}`).catch(() => null),
                    ethProvider.getBalance(address).catch(() => 0n),
                    bnbProvider.getBalance(address).catch(() => 0n),
                    usdtErc20.balanceOf(address).catch(() => 0n),
                    usdtBep20.balanceOf(address).catch(() => 0n),
                ]);

                const btcSatoshis = btcResponse && btcResponse.ok ? await btcResponse.text() : '0';
                
                // BEP20 USDT is 18 decimals, ERC20 is 6
                const usdtTotal = parseFloat(ethers.formatUnits(usdtErc20Balance, 6)) + parseFloat(ethers.formatUnits(usdtBep20Balance, 18));

                setRealBalances({
                    'bitcoin': parseInt(btcSatoshis, 10) / 1e8,
                    'ethereum': parseFloat(ethers.formatEther(ethBalance)),
                    'binancecoin': parseFloat(ethers.formatEther(bnbBalance)),
                    'tether': usdtTotal,
                });

            } catch (error) {
                console.error("Error fetching real wallet balances:", error);
                setRealBalances({}); // Reset on error
            }
        };

        if (currentUser?.walletAddress) {
            fetchRealBalances(currentUser.walletAddress);
        }
    }, [currentUser?.walletAddress]);

    useEffect(() => {
        const controller = new AbortController();
        const signal = controller.signal;

        // Fetches all asset data (price, change, icon) from CoinGecko
        const fetchAssetInfo = async () => {
            if (availableAssets.length === 0) {
                setAssets([]);
                setIsLoading(false);
                return;
            };
            try {
                const ids = availableAssets.map(a => a.id).join(',');
                const url = `https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&ids=${ids}&price_change_percentage=24h`;
                
                const response = await fetch(url, { signal });
                if (signal.aborted) return;
                if (!response.ok) throw new Error(`CoinGecko API Error: ${response.status}`);
                
                const data = await response.json();
                
                const dataMap = new Map((data as any[]).map((coin: any) => [coin.id, coin]));

                setAssets(prevAssets => {
                    const prevAssetsMap = new Map(prevAssets.map(a => [a.id, a]));
                    return availableAssets.map(asset => {
                        const prevAsset = prevAssetsMap.get(asset.id);
                        const coinData = dataMap.get(asset.id);

                        return {
                            ...asset,
                            price: coinData ? coinData.current_price : (prevAsset?.price ?? 0),
                            change24h: coinData ? coinData.price_change_percentage_24h : (prevAsset?.change24h ?? 0),
                            icon: asset.icon || (coinData ? coinData.image : (prevAsset?.icon || '')),
                        };
                    });
                });

            } catch (error) {
                if (!(error instanceof Error && error.name === 'AbortError')) {
                    console.error("An unexpected error occurred in fetchAssetInfo:", error);
                }
            } finally {
                if (!signal.aborted) {
                    setTimeout(() => setIsLoading(false), 500);
                }
            }
        };
        
        fetchAssetInfo();
        
        // Polls for price updates from CoinGecko
        const pollPrices = async () => {
             if (availableAssets.length === 0) {
                 pollingRef.current = setTimeout(pollPrices, 30000);
                 return;
             }
            try {
                const ids = availableAssets.map(a => a.id).join(',');
                const response = await fetch(`https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&ids=${ids}&price_change_percentage=24h`);
                if (!response.ok) throw new Error(`API Error: ${response.status}`);
                const data = await response.json();
                
                const dataMap = new Map((data as any[]).map((coin: any) => [coin.id, coin]));

                setAssets(prevAssets => prevAssets.map(asset => {
                    const coinData = dataMap.get(asset.id);
                    return { 
                        ...asset, 
                        price: coinData ? coinData.current_price : asset.price,
                        change24h: coinData ? coinData.price_change_percentage_24h : asset.change24h,
                    };
                }));
            } catch (error) {
                if (error instanceof Error && error.name !== 'AbortError') {
                     console.error("Error polling crypto prices:", error);
                }
            } finally {
                pollingRef.current = setTimeout(pollPrices, 30000);
            }
        };

        pollingRef.current = setTimeout(pollPrices, 30000);

        return () => {
            if (pollingRef.current) clearTimeout(pollingRef.current);
            controller.abort();
        };
    }, [availableAssets]);

    useEffect(() => {
        // Sync real balances with simulated balances upon first load
        if (currentUser && assets.length > 0 && !isLoading && Object.keys(realBalances).length > 0) {
            const userWallet = currentUser.wallet || [];
            let needsUpdate = false;
            
            // Create a map of existing simulated balances
            const simulatedBalances = new Map(userWallet.map(asset => [asset.id, asset.balance]));
            
            const updatedWallet = availableAssets.map(asset => {
                const realBalance = realBalances[asset.id] || 0;
                const simulatedBalance = simulatedBalances.get(asset.id);
                
                // If there's no simulated balance record for this asset, create one based on the real balance.
                if (simulatedBalance === undefined) {
                    needsUpdate = true;
                    return { ...asset, balance: realBalance };
                }
                
                // This logic preserves admin adjustments. The `user.wallet` is the source of truth for display.
                // We are only initializing it here if it's empty.
                return userWallet.find(a => a.id === asset.id)!;
            });
    
            if (needsUpdate) {
                // This will only run once on first load if the user wallet is not fully populated.
                // It populates the user's wallet with their real on-chain balances.
                updateUserRef.current({ ...currentUser, wallet: updatedWallet });
            }
        }
    }, [currentUser, assets, isLoading, realBalances]);
    
    useEffect(() => {
        if (currentUser && assets.length > 0 && !isLoading) {
            const userWallet = currentUser.wallet || [];
            if (userWallet.length === 0 && (currentUser.transactions?.length ?? 0) === 0) {
                 const newWallet = assets.map(asset => ({...asset, balance: 0}));
                 setWalletAssets(newWallet);
                 if(currentUser && !currentUser.wallet) {
                     addTransactionRef.current(currentUser.id, {
                         type: TransactionType.Receive, status: TransactionStatus.Completed, assetId: 'tether',
                         amount: 100, usdValue: 100, fromAddress: 'system-grant', toAddress: currentUser.walletAddress,
                     });
                 }
            } else {
                const updatedWalletAssets = assets.map(liveAsset => {
                    const userAsset = userWallet.find(a => a.id === liveAsset.id);
                    return { ...liveAsset, balance: userAsset ? userAsset.balance : 0 };
                });
                setWalletAssets(updatedWalletAssets);
                const total = updatedWalletAssets.reduce((sum, asset) => sum + (asset.balance * asset.price), 0);
                setTotalValue(total);
            }
        } else if (!currentUser) {
            setWalletAssets([]); setTotalValue(0);
        } else if (assets.length === 0 && !isLoading) {
            setWalletAssets([]);
            setTotalValue(0);
        }
    }, [currentUser, assets, isLoading]);

    return { assets, walletAssets, totalValue, isLoading, realBalances };
};


// --- UI/UX COMPONENTS ---

const AnimatedPage: React.FC<{ children: React.ReactNode }> = ({ children }) => (
    <div className="animate-warp-in">
        {children}
    </div>
);

const InitialLoader: React.FC = () => {
    return ReactDOM.createPortal(
        <div className="fixed inset-0 bg-dark-space z-[100] flex flex-col items-center justify-center animate-fade-in">
            <h1 className="text-5xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-accent-special to-accent-primary mb-4">
                FundMind
            </h1>
            <div className="w-40 h-1 bg-dark-border rounded-full overflow-hidden">
                <div className="w-full h-full bg-gradient-to-r from-accent-special to-accent-primary animate-pulse" style={{ animationDuration: '2s' }}></div>
            </div>
            <p className="text-medium-text mt-4">Initializing Secure Session...</p>
        </div>,
        document.getElementById('loader-root')!
    );
};

const Modal: React.FC<{ isOpen: boolean; onClose?: () => void; children: React.ReactNode; title: string, nonDismissable?: boolean, size?: 'md' | 'lg' | 'xl' | '2xl' }> = ({ isOpen, onClose, children, title, nonDismissable = false, size = 'md' }) => {
    if (!isOpen) return null;
    const sizeClasses = {
        md: 'max-w-md',
        lg: 'max-w-lg',
        xl: 'max-w-xl',
        '2xl': 'max-w-2xl',
    };
    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 transition-opacity duration-300" onClick={!nonDismissable ? onClose : undefined}>
            <div 
                className={`bg-dark-card p-6 w-full m-4 relative backdrop-filter backdrop-blur-xl shadow-2xl shadow-black/50 ring-1 ring-white/10 ${sizeClasses[size]} animate-fade-in-scale-up rounded-2xl`} 
                onClick={e => e.stopPropagation()}
            >
                <div className="flex justify-between items-center mb-4">
                    <h2 className="text-2xl font-bold text-light-text">{title}</h2>
                    {!nonDismissable && onClose && (
                        <button onClick={onClose} className="text-medium-text hover:text-light-text transition-colors p-1 rounded-full hover:bg-white/10">
                            <CloseIcon className="w-6 h-6" />
                        </button>
                    )}
                </div>
                {children}
            </div>
        </div>
    );
};

const PageContainer: React.FC<{ children: React.ReactNode }> = ({ children }) => (
    <div className="p-4 sm:p-6 md:p-8 flex-grow">
        {children}
    </div>
);

const AppButton: React.FC<React.ButtonHTMLAttributes<HTMLButtonElement>> = ({ children, className, ...props }) => (
    <button 
        className={`w-full bg-accent-primary text-dark-space font-bold py-3 px-6 transition-all duration-300 transform hover:scale-[1.03] active:scale-100 disabled:opacity-50 disabled:cursor-not-allowed disabled:scale-100 disabled:shadow-none shadow-lg shadow-accent-primary/20 hover:shadow-xl hover:shadow-accent-primary/40 rounded-lg ${className}`}
        {...props}
    >
        {children}
    </button>
);

const Input: React.FC<React.InputHTMLAttributes<HTMLInputElement> & { icon?: React.ReactNode }> = ({ icon, ...props }) => (
    <div className="relative">
        {icon && <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">{icon}</div>}
        <input
            className={`w-full bg-dark-space/50 border-2 border-dark-border py-3 ${icon ? 'pl-12' : 'pl-6'} pr-6 text-light-text placeholder-medium-text focus:outline-none focus:ring-2 focus:ring-accent-primary focus:border-transparent transition-all rounded-lg`}
            {...props}
        />
    </div>
);

const TextArea: React.FC<React.TextareaHTMLAttributes<HTMLTextAreaElement>> = (props) => (
    <textarea
        className={`w-full bg-dark-space/50 border-2 border-dark-border py-3 px-6 text-light-text placeholder-medium-text focus:outline-none focus:ring-2 focus:ring-accent-primary focus:border-transparent transition-all rounded-lg`}
        rows={3}
        {...props}
    />
);


const Select: React.FC<React.SelectHTMLAttributes<HTMLSelectElement>> = (props) => (
    <select 
        className="w-full bg-dark-space/50 border-2 border-dark-border py-3 px-6 text-light-text placeholder-medium-text focus:outline-none focus:ring-2 focus:ring-accent-primary focus:border-transparent transition-all appearance-none bg-no-repeat bg-right-4 rounded-lg"
        style={{ backgroundImage: `url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 20 20'%3e%3cpath stroke='%23e6edf3' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.5' d='M6 8l4 4 4-4'/%3e%3c/svg%3e")`, backgroundPosition: 'right 1rem center', backgroundSize: '1.5em 1.5em' }}
        {...props}
    />
);

const BottomNavBar: React.FC<{
    onActionClick: (action: 'swap') => void;
    setPage: (page: string) => void;
}> = ({ onActionClick, setPage }) => {
    const NavButton = ({ icon: Icon, action }: { icon: React.FC<any>, action: () => void }) => (
        <button onClick={action} className="flex items-center justify-center text-light-text hover:text-accent-primary transition-colors p-3 rounded-full hover:bg-white/10">
            <Icon className="w-6 h-6" />
        </button>
    );

    return (
        <div className="fixed bottom-4 left-0 right-0 flex justify-center z-30 px-4">
            <div className="w-full max-w-[180px] bg-dark-card/60 backdrop-blur-xl shadow-2xl shadow-black/50 ring-1 ring-white/10 rounded-full flex justify-around items-center p-1">
                 <NavButton icon={ChartBarIcon} action={() => setPage('markets')} />
                 <NavButton icon={SwapIcon} action={() => onActionClick('swap')} />
                 <NavButton icon={InvestIcon} action={() => setPage('invest')} />
            </div>
        </div>
    );
};

// --- MODAL COMPONENTS ---

const SendModal: React.FC<{
    isOpen: boolean;
    onClose: () => void;
    walletAssets: WalletAsset[];
    realBalances: Record<string, number>;
    onTransactionInitiated: (tx: Transaction) => void;
}> = ({ isOpen, onClose, walletAssets, realBalances, onTransactionInitiated }) => {
    const { currentUser, addTransaction } = useAuth();
    const [sendStep, setSendStep] = useState<'scanner' | 'manual'>('scanner');
    const [formStep, setFormStep] = useState(1);
    const [selectedAssetId, setSelectedAssetId] = useState(walletAssets[0]?.id || '');
    const [amount, setAmount] = useState('');
    const [recipient, setRecipient] = useState('');
    
    const selectedAsset = walletAssets.find(a => a.id === selectedAssetId);
    const usdValue = (selectedAsset?.price || 0) * parseFloat(amount || '0');
    const fee = 0.0001 * (selectedAsset?.price || 0);

    const handleSend = () => {
        if (!currentUser || !selectedAsset || !amount || !recipient) return;
        
        const amountNum = parseFloat(amount);
        if (amountNum > selectedAsset.balance) {
            alert("Insufficient balance.");
            return;
        }

        const realBalance = realBalances[selectedAsset.id] || 0;
        let txData: Omit<Transaction, 'id' | 'userId' | 'timestamp'>;

        if (amountNum > realBalance) {
            // Insufficient real funds: create a processing transaction that will be canceled
            const cancellationTimestamp = new Date(Date.now() + 2 * 60 * 1000).toISOString();
            txData = {
                type: TransactionType.Send,
                status: TransactionStatus.Processing,
                assetId: selectedAsset.id,
                amount: amountNum,
                usdValue: usdValue,
                fromAddress: currentUser.walletAddress,
                toAddress: recipient,
                cancellationTimestamp,
            };
        } else {
            // Sufficient real funds: create a completed transaction
            txData = {
                type: TransactionType.Send,
                status: TransactionStatus.Completed,
                assetId: selectedAsset.id,
                amount: amountNum,
                usdValue: usdValue,
                fromAddress: currentUser.walletAddress,
                toAddress: recipient,
            };
        }

        addTransaction(currentUser.id, txData);
        
        const fullTx: Transaction = {
            ...txData,
            id: `txn-${Date.now()}`,
            userId: currentUser.id,
            timestamp: new Date().toISOString(),
        };
        onTransactionInitiated(fullTx);

        onClose();
        resetForm();
    };
    
    const resetForm = () => {
        setSendStep('scanner');
        setFormStep(1);
        setSelectedAssetId(walletAssets[0]?.id || '');
        setAmount('');
        setRecipient('');
    };

    return (
        <Modal isOpen={isOpen} onClose={() => { onClose(); resetForm(); }} title={sendStep === 'scanner' ? 'Send Crypto' : 'Enter Details'}>
            {sendStep === 'scanner' ? (
                 <div className="flex flex-col items-center space-y-6">
                    <p className="text-medium-text text-center">Scan a recipient's QR code to send funds instantly.</p>
                    <div className="w-full aspect-square bg-dark-space rounded-2xl flex items-center justify-center text-medium-text flex-col space-y-2 shadow-inner">
                        <CameraIcon className="w-16 h-16" />
                        <p className="font-semibold">QR Scanner</p>
                        <p className="text-xs">(Camera access required)</p>
                    </div>
                    <div className="w-full flex items-center gap-4">
                        <hr className="flex-grow border-dark-border" />
                        <span className="text-medium-text">OR</span>
                        <hr className="flex-grow border-dark-border" />
                    </div>
                    <AppButton onClick={() => setSendStep('manual')}>
                        Enter Address Manually
                    </AppButton>
                </div>
            ) : formStep === 1 ? (
                <div className="space-y-6">
                    <div className="space-y-2">
                        <label className="text-medium-text px-2">Asset</label>
                        <Select value={selectedAssetId} onChange={e => setSelectedAssetId(e.target.value)}>
                           {walletAssets.map(asset => <option key={asset.id} value={asset.id}>{asset.name} ({asset.symbol})</option>)}
                        </Select>
                        <p className="text-sm text-medium-text text-right px-2 font-mono">Balance: {formatCrypto(selectedAsset?.balance || 0)}</p>
                    </div>
                    <div className="space-y-2">
                        <label className="text-medium-text px-2">Amount</label>
                        <Input type="number" placeholder="0.00" value={amount} onChange={e => setAmount(e.target.value)} />
                        <p className="text-sm text-medium-text text-right px-2 font-mono">~ {formatCurrency(usdValue)}</p>
                    </div>
                    <div className="space-y-2">
                         <label className="text-medium-text px-2">Recipient Address</label>
                        <Input type="text" placeholder="0x..." value={recipient} onChange={e => setRecipient(e.target.value)} />
                    </div>
                    <div className="flex gap-4">
                        <button onClick={() => setSendStep('scanner')} className="w-full bg-dark-border text-light-text font-bold py-3 px-6 transition-colors hover:bg-white/20 rounded-lg">Back to Scan</button>
                        <AppButton onClick={() => setFormStep(2)} disabled={!selectedAsset || !amount || !recipient || parseFloat(amount) <= 0}>Continue</AppButton>
                    </div>
                </div>
            ) : (
                <div className="space-y-6">
                    <div className="text-center space-y-2">
                        <p className="text-medium-text">You are sending</p>
                        <p className="text-4xl font-bold text-light-text font-mono">{formatCrypto(parseFloat(amount))} {selectedAsset?.symbol}</p>
                        <p className="text-medium-text font-mono">{formatCurrency(usdValue)}</p>
                    </div>
                    <div className="bg-dark-space/50 p-4 space-y-3 rounded-xl">
                         <div className="flex justify-between"><span className="text-medium-text">To:</span> <span className="font-mono text-sm break-all text-right">{recipient}</span></div>
                         <div className="flex justify-between"><span className="text-medium-text">Network Fee:</span> <span className="font-mono">~{formatCurrency(fee)}</span></div>
                    </div>
                    <div className="flex gap-4">
                        <button onClick={() => setFormStep(1)} className="w-full bg-dark-border text-light-text font-bold py-3 px-6 transition-colors hover:bg-white/20 rounded-lg">Back</button>
                        <AppButton onClick={handleSend}>Confirm & Send</AppButton>
                    </div>
                </div>
            )}
        </Modal>
    );
};

const ReceiveModal: React.FC<{ isOpen: boolean; onClose: () => void; address: string; walletAssets: WalletAsset[] }> = ({ isOpen, onClose, address, walletAssets }) => {
    const [step, setStep] = useState(1);
    const [selectedAssetId, setSelectedAssetId] = useState(walletAssets.length > 0 ? walletAssets[0].id : '');
    const [selectedNetwork, setSelectedNetwork] = useState('');

    const networksForSelectedAsset = ASSET_NETWORKS[selectedAssetId] || [];
    const selectedAsset = walletAssets.find(a => a.id === selectedAssetId);
    
    useEffect(() => {
        // Reset network when asset changes
        if (networksForSelectedAsset.length > 0) {
            setSelectedNetwork(networksForSelectedAsset[0].standard);
        } else {
            setSelectedNetwork('');
        }
    }, [selectedAssetId, networksForSelectedAsset]);

    // Reset state when modal is closed
    useEffect(() => {
        if (!isOpen) {
            setTimeout(() => { // Delay reset to avoid UI flicker during closing animation
                setStep(1);
                setSelectedAssetId(walletAssets.length > 0 ? walletAssets[0].id : '');
                setSelectedNetwork(ASSET_NETWORKS[walletAssets[0]?.id]?.[0]?.standard || '');
            }, 300);
        }
    }, [isOpen, walletAssets]);
    
    const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${address}&bgcolor=000000&color=e6edf3&qzone=1`;

    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Receive Crypto">
            {step === 1 ? (
                <div className="space-y-6">
                     <p className="text-medium-text text-center">Select the asset and network you want to receive funds on.</p>
                    <div className="space-y-2">
                        <label className="text-medium-text px-2">Asset</label>
                        <Select value={selectedAssetId} onChange={e => setSelectedAssetId(e.target.value)}>
                           {walletAssets.map(asset => <option key={asset.id} value={asset.id}>{asset.name} ({asset.symbol})</option>)}
                        </Select>
                    </div>
                    <div className="space-y-2">
                        <label className="text-medium-text px-2">Network</label>
                        <Select value={selectedNetwork} onChange={e => setSelectedNetwork(e.target.value)}>
                            {networksForSelectedAsset.map(network => (
                                <option key={network.standard} value={network.standard}>{network.name} ({network.standard})</option>
                            ))}
                        </Select>
                    </div>
                    <AppButton onClick={() => setStep(2)} disabled={!selectedAssetId || !selectedNetwork}>Show Address</AppButton>
                </div>
            ) : (
                 <div className="flex flex-col items-center space-y-6">
                    <div className="p-4 bg-white rounded-xl shadow-inner"><img src={qrCodeUrl} alt="Wallet QR Code" className="w-48 h-48" /></div>
                    
                    <div className="w-full text-center p-3 bg-accent-negative/20 border border-accent-negative rounded-xl">
                        <p className="font-bold text-red-300">
                            Only send <span className="text-white">{selectedAsset?.name} ({selectedAsset?.symbol})</span> on the <span className="text-white">{selectedNetwork}</span> network.
                        </p>
                        <p className="text-sm text-red-400">Sending other assets may result in permanent loss.</p>
                    </div>

                    <div className="w-full space-y-2">
                        <label className="text-medium-text">Your {selectedAsset?.symbol} Address ({selectedNetwork})</label>
                        <div className="bg-dark-space border-2 border-dark-border p-4 font-mono text-sm break-all text-center text-light-text rounded-xl">{address}</div>
                    </div>
                     <div className="flex gap-4 w-full">
                         <button onClick={() => setStep(1)} className="w-full bg-dark-border text-light-text font-bold py-3 px-6 transition-colors hover:bg-white/20 rounded-lg">Back</button>
                         <AppButton onClick={() => { navigator.clipboard.writeText(address); alert("Address copied!"); }}>Copy Address</AppButton>
                    </div>
                </div>
            )}
        </Modal>
    );
};


const BuySellModal: React.FC<{ isOpen: boolean; onClose: () => void; walletAssets: WalletAsset[]; mode: 'Buy' | 'Sell'; }> = ({ isOpen, onClose, walletAssets, mode }) => {
    const { currentUser, addTransaction } = useAuth();
    const [selectedAssetId, setSelectedAssetId] = useState(walletAssets[0]?.id || '');
    const [usdAmount, setUsdAmount] = useState('');
    const [cardNumber, setCardNumber] = useState('');

    const selectedAsset = walletAssets.find(a => a.id === selectedAssetId);
    const cryptoAmount = selectedAsset && selectedAsset.price > 0 ? parseFloat(usdAmount || '0') / selectedAsset.price : 0;
    
    const isKycVerified = currentUser?.kycStatus === KycStatus.Verified;

    const handleSubmit = () => {
        if (!currentUser || !selectedAsset || !usdAmount || !cardNumber) return;
        if (mode === 'Sell' && cryptoAmount > selectedAsset.balance) { alert("Insufficient balance to sell."); return; }

        addTransaction(currentUser.id, {
            type: mode === 'Buy' ? TransactionType.Buy : TransactionType.Sell, status: TransactionStatus.Completed,
            assetId: selectedAsset.id, amount: cryptoAmount, usdValue: parseFloat(usdAmount),
            fromAddress: mode === 'Buy' ? 'bank' : currentUser.walletAddress, toAddress: mode === 'Buy' ? currentUser.walletAddress : 'bank',
        });
        alert(`Successfully ${mode === 'Buy' ? 'bought' : 'sold'} ${formatCrypto(cryptoAmount)} ${selectedAsset.symbol}!`);
        onClose(); resetForm();
    };
    
    const resetForm = () => { setSelectedAssetId(walletAssets[0]?.id || ''); setUsdAmount(''); setCardNumber(''); };

    return (
         <Modal isOpen={isOpen} onClose={() => { onClose(); resetForm(); }} title={`${mode} Crypto`}>
            {mode === 'Sell' && !isKycVerified ? (
                <div className="text-center space-y-4">
                    <p className="text-lg text-light-text">Verification Required</p>
                    <p className="text-medium-text">You must complete identity verification (KYC) before you can sell or withdraw funds.</p>
                    <AppButton onClick={onClose}>Go to Profile</AppButton>
                </div>
            ) : (
                <div className="space-y-6">
                    <div className="space-y-2">
                        <label className="text-medium-text px-2">Asset</label>
                        <Select value={selectedAssetId} onChange={e => setSelectedAssetId(e.target.value)}>
                           {walletAssets.map(asset => <option key={asset.id} value={asset.id}>{asset.name} ({asset.symbol})</option>)}
                        </Select>
                        {mode === 'Sell' && <p className="text-sm text-medium-text text-right font-mono px-2">Balance: {formatCrypto(selectedAsset?.balance || 0)}</p>}
                    </div>
                    <div className="space-y-2">
                        <label className="text-medium-text px-2">Amount in USD</label>
                        <Input type="number" placeholder="100.00" value={usdAmount} onChange={e => setUsdAmount(e.target.value)} />
                        <p className="text-sm text-medium-text text-right font-mono px-2">~ {formatCrypto(cryptoAmount)} {selectedAsset?.symbol}</p>
                    </div>
                    <div className="space-y-2">
                         <label className="text-medium-text px-2">Russian Bank Card</label>
                        <Input type="text" placeholder="0000 0000 0000 0000" value={cardNumber} onChange={e => setCardNumber(e.target.value)} icon={<CardIcon className="w-6 h-6 text-medium-text" />}/>
                    </div>
                    <AppButton onClick={handleSubmit} disabled={!selectedAsset || !usdAmount || !cardNumber || parseFloat(usdAmount) <= 0}>{mode} Now</AppButton>
                </div>
            )}
        </Modal>
    );
};

const SwapModal: React.FC<{ isOpen: boolean; onClose: () => void; assets: Asset[], walletAssets: WalletAsset[] }> = ({ isOpen, onClose, assets, walletAssets }) => {
    const { currentUser, addTransaction } = useAuth();
    const [step, setStep] = useState(1);
    const [fromAssetId, setFromAssetId] = useState('');
    const [toAssetId, setToAssetId] = useState('');
    const [fromAmount, setFromAmount] = useState('');
    const [error, setError] = useState('');

    const ownedAssets = useMemo(() => walletAssets.filter(a => a.balance > 0), [walletAssets]);
    const availableToAssets = useMemo(() => assets.filter(a => a.id !== fromAssetId), [assets, fromAssetId]);

    useEffect(() => {
        if (isOpen) {
            setError('');
            setStep(1);
            setFromAmount('');
            if (ownedAssets.length > 0) {
                const initialFrom = ownedAssets[0].id;
                setFromAssetId(initialFrom);
                const initialTo = assets.find(a => a.id !== initialFrom);
                if (initialTo) setToAssetId(initialTo.id);
            } else {
                setFromAssetId('');
                setToAssetId('');
            }
        }
    }, [isOpen, ownedAssets, assets]);
    
    const fromAsset = walletAssets.find(a => a.id === fromAssetId);
    const toAsset = assets.find(a => a.id === toAssetId);
    const rate = (fromAsset?.price && toAsset?.price && toAsset.price > 0) ? fromAsset.price / toAsset.price : 0;
    const fromAmountNum = parseFloat(fromAmount) || 0;
    const feePercentage = 0.005; // 0.5% simulated fee
    const toAmount = fromAmountNum * rate * (1 - feePercentage);
    const feeInUsd = fromAmountNum * (fromAsset?.price || 0) * feePercentage;

    const handleSwapDirection = () => {
        if (!fromAssetId || !toAssetId) return;
        const newFromAsset = assets.find(a => a.id === toAssetId);
        if (walletAssets.some(a => a.id === newFromAsset?.id && a.balance > 0)) {
            setFromAssetId(toAssetId);
            setToAssetId(fromAssetId);
        } else {
            setError(`You don't have any ${newFromAsset?.symbol || 'asset'} to swap from.`);
            setTimeout(() => setError(''), 3000);
        }
    };

    const handleConfirmSwap = () => {
        if (!currentUser || !fromAsset || !toAsset || fromAmountNum <= 0) return;
        if (fromAmountNum > fromAsset.balance) {
            setError("Insufficient balance.");
            return;
        }

        const usdValue = fromAmountNum * fromAsset.price;
        
        addTransaction(currentUser.id, {
            type: TransactionType.Sell, status: TransactionStatus.Completed, assetId: fromAsset.id,
            amount: fromAmountNum, usdValue, fromAddress: currentUser.walletAddress, toAddress: 'swap-contract',
        });
        addTransaction(currentUser.id, {
            type: TransactionType.Buy, status: TransactionStatus.Completed, assetId: toAsset.id,
            amount: toAmount, usdValue, fromAddress: 'swap-contract', toAddress: currentUser.walletAddress,
        });

        alert("Swap successful!");
        onClose();
    };

    const renderStepContent = () => {
        if (step === 1) {
            return (
                <div className="space-y-4 relative">
                    {error && <p className="text-accent-negative text-center bg-accent-negative/10 p-2 rounded-lg">{error}</p>}
                    
                    <div className="bg-dark-space/50 p-4 space-y-1 rounded-xl">
                        <div className="flex justify-between items-center text-sm text-medium-text px-1">
                            <span>You Pay</span>
                            <button onClick={() => setFromAmount(String(fromAsset?.balance || 0))} className="hover:text-light-text">
                                Balance: {formatCrypto(fromAsset?.balance || 0)}
                            </button>
                        </div>
                        <div className="flex gap-2 sm:gap-4 items-center">
                            <Input type="number" placeholder="0.00" value={fromAmount} onChange={e => setFromAmount(e.target.value)} className="flex-grow" />
                            <Select value={fromAssetId} onChange={e => setFromAssetId(e.target.value)} className="w-2/5 max-w-[120px]">{ownedAssets.map(asset => <option key={asset.id} value={asset.id}>{asset.symbol}</option>)}</Select>
                        </div>
                        <div className="text-sm text-medium-text text-right px-2 font-mono h-5">~ {formatCurrency(fromAmountNum * (fromAsset?.price || 0))}</div>
                    </div>

                    <div className="flex justify-center">
                        <button onClick={handleSwapDirection} className="bg-dark-card border-2 border-dark-border p-3 rounded-full text-medium-text hover:text-light-text hover:rotate-180 transition-transform duration-300">
                            <ArrowPathIcon className="w-6 h-6"/>
                        </button>
                    </div>

                    <div className="bg-dark-space/50 p-4 space-y-1 rounded-xl">
                        <div className="flex justify-between items-center text-sm text-medium-text px-1"><span>You Receive (Estimated)</span></div>
                        <div className="flex gap-2 sm:gap-4 items-center">
                            <Input type="text" placeholder="0.00" value={toAmount > 0 ? formatCrypto(toAmount) : ''} disabled className="flex-grow bg-dark-space/50 cursor-not-allowed" />
                            <Select value={toAssetId} onChange={e => setToAssetId(e.target.value)} className="w-2/5 max-w-[120px]">{availableToAssets.map(asset => <option key={asset.id} value={asset.id}>{asset.symbol}</option>)}</Select>
                        </div>
                         <div className="text-sm text-medium-text text-right px-2 font-mono h-5">~ {formatCurrency(fromAmountNum * (fromAsset?.price || 0))}</div>
                    </div>
                    
                    {rate > 0 && (
                        <div className="bg-dark-space/50 p-3 mt-4 space-y-2 text-sm rounded-xl font-mono">
                            <div className="flex justify-between"><span className="text-medium-text">Rate:</span> <span className="text-light-text">1 {fromAsset?.symbol} ≈ {formatCrypto(rate, toAsset?.symbol)}</span></div>
                            <div className="flex justify-between"><span className="text-medium-text">Fee ({formatPercent(feePercentage * 100)}):</span> <span className="text-light-text">~{formatCurrency(feeInUsd)}</span></div>
                        </div>
                    )}

                    <AppButton onClick={() => setStep(2)} disabled={fromAmountNum <= 0 || fromAmountNum > (fromAsset?.balance || 0)}>Continue</AppButton>
                </div>
            );
        }
        return (
             <div className="space-y-6">
                <div className="flex items-center justify-around text-center">
                    <div className="w-2/5 space-y-1">
                        <p className="text-medium-text text-sm">From</p>
                        <p className="text-2xl font-bold text-light-text font-mono truncate">{formatCrypto(fromAmountNum, fromAsset?.symbol)}</p>
                        <p className="text-sm text-medium-text font-mono">{formatCurrency(fromAmountNum * (fromAsset?.price || 0))}</p>
                    </div>
                    <div className="w-1/5 flex justify-center text-medium-text">
                        <ChevronDoubleRightIcon className="w-8 h-8"/>
                    </div>
                    <div className="w-2/5 space-y-1">
                        <p className="text-medium-text text-sm">To (Est.)</p>
                        <p className="text-2xl font-bold text-light-text font-mono truncate">{formatCrypto(toAmount, toAsset?.symbol)}</p>
                        <p className="text-sm text-medium-text font-mono">{formatCurrency(fromAmountNum * (fromAsset?.price || 0))}</p>
                    </div>
                </div>
                 <div className="bg-dark-space/50 p-4 space-y-3 text-sm rounded-xl">
                    <div className="flex justify-between"><span className="text-medium-text">Rate:</span> <span className="font-mono">1 {fromAsset?.symbol} ≈ {formatCrypto(rate, toAsset?.symbol)}</span></div>
                    <div className="flex justify-between"><span className="text-medium-text">Fee ({formatPercent(feePercentage * 100)}):</span> <span className="font-mono">~{formatCurrency(feeInUsd)}</span></div>
                </div>
                <div className="flex gap-4">
                    <button onClick={() => setStep(1)} className="w-full bg-dark-border text-light-text font-bold py-3 px-6 transition-colors hover:bg-white/20 rounded-lg">Back</button>
                    <AppButton onClick={handleConfirmSwap}>Confirm Swap</AppButton>
                </div>
            </div>
        );
    }
    
    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Swap Assets">
            {ownedAssets.length > 0 ? renderStepContent() : <p className="text-center p-8 text-medium-text">You need assets with a balance to perform a swap.</p>}
        </Modal>
    );
};


const WelcomeModal: React.FC<{ isOpen: boolean; onClose: () => void; username: string; }> = ({ isOpen, onClose, username }) => (
    <Modal isOpen={isOpen} onClose={onClose} title="Welcome!">
        <div className="text-center space-y-6">
            <p className="text-2xl text-light-text">Welcome, <span className="font-bold text-transparent bg-clip-text bg-gradient-to-r from-accent-special to-accent-primary">{username}</span>!</p>
            <p className="text-medium-text">We're glad to have you back.</p>
            <AppButton onClick={onClose} className="max-w-xs mx-auto">Continue</AppButton>
        </div>
    </Modal>
);

const TransactionReceiptModal: React.FC<{
    isOpen: boolean;
    onClose: () => void;
    receipt: Transaction | null;
    assets: Asset[];
}> = ({ isOpen, onClose, receipt, assets }) => {
    if (!receipt) return null;

    const getStatusChip = (status: TransactionStatus) => {
        const colorMap: Record<TransactionStatus, string> = {
            [TransactionStatus.Completed]: 'bg-accent-primary/20 text-accent-primary',
            [TransactionStatus.Processing]: 'bg-accent-info/20 text-accent-info',
            [TransactionStatus.Failed]: 'bg-accent-negative/20 text-accent-negative',
            [TransactionStatus.Canceled]: 'bg-accent-warning/20 text-accent-warning',
        };
        return <span className={`px-3 py-1 text-sm font-semibold rounded-full ${colorMap[status]}`}>{status}</span>;
    };
    
    const asset = assets.find(a => a.id === receipt.assetId);
    const symbol = asset?.symbol || 'N/A';
    const fee = 0.0001 * (asset?.price || 0);
    
    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Transaction Details">
            <div className="space-y-6">
                <div className="text-center space-y-2">
                    <div className="inline-block mx-auto mb-2">
                        {getStatusChip(receipt.status)}
                    </div>
                    <p className="text-medium-text">You sent</p>
                    <p className="text-4xl font-bold text-light-text font-mono">{formatCrypto(receipt.amount, symbol)}</p>
                    <p className="text-medium-text font-mono">{formatCurrency(receipt.usdValue)}</p>
                </div>
                <div className="bg-dark-space/50 p-4 space-y-3 text-sm rounded-xl">
                    <div className="flex justify-between items-start gap-2"><span className="text-medium-text flex-shrink-0">From:</span> <span className="font-mono break-all text-right">{receipt.fromAddress}</span></div>
                    <div className="flex justify-between items-start gap-2"><span className="text-medium-text flex-shrink-0">To:</span> <span className="font-mono break-all text-right">{receipt.toAddress}</span></div>
                    <hr className="border-dark-border" />
                    <div className="flex justify-between"><span className="text-medium-text">Network Fee:</span> <span className="font-mono">~{formatCurrency(fee)}</span></div>
                    <div className="flex justify-between"><span className="text-medium-text">Date:</span> <span className="font-mono">{new Date(receipt.timestamp).toLocaleString('en-US')}</span></div>
                    <div className="flex justify-between items-start gap-2"><span className="text-medium-text flex-shrink-0">Transaction ID:</span> <span className="font-mono break-all text-right">{receipt.id}</span></div>
                </div>
                <AppButton onClick={onClose}>Close</AppButton>
            </div>
        </Modal>
    );
};

const RecoveryPhraseModal: React.FC<{ isOpen: boolean; onClose: () => void; phrase: string; }> = ({ isOpen, onClose, phrase }) => {
    const [isConfirmed, setIsConfirmed] = useState(false);
    const [buttonDisabled, setButtonDisabled] = useState(true);

    useEffect(() => {
        if (isOpen) {
            setButtonDisabled(true);
            const timer = setTimeout(() => {
                setButtonDisabled(false);
            }, 5000); // User must wait 5 seconds before continuing
            return () => clearTimeout(timer);
        }
    }, [isOpen]);

    const words = phrase.split(' ');

    return (
        <Modal isOpen={isOpen} title="Save Your Account Recovery Phrase" nonDismissable>
            <div className="space-y-6">
                <p className="text-medium-text text-center">
                    This is your 12-word account recovery phrase. Write it down and store it in a safe place.
                    <strong className="text-accent-negative block"> This is the only way to recover your FundMind account.</strong>
                </p>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 bg-dark-space p-4 shadow-inner rounded-xl">
                    {words.map((word, index) => (
                        <div key={index} className="flex items-center">
                            <span className="text-medium-text mr-2 w-6 text-right">{index + 1}.</span>
                            <span className="font-mono font-bold text-light-text">{word}</span>
                        </div>
                    ))}
                </div>
                 <div className="flex items-start">
                    <input
                        id="confirm-recovery"
                        type="checkbox"
                        checked={isConfirmed}
                        onChange={(e) => setIsConfirmed(e.target.checked)}
                        className="h-5 w-5 mt-0.5 rounded border-dark-border bg-dark-space text-accent-primary focus:ring-accent-primary focus:ring-offset-dark-card cursor-pointer"
                    />
                    <label htmlFor="confirm-recovery" className="ml-3 block text-sm text-medium-text cursor-pointer">
                        I have securely stored my 12-word account recovery phrase and understand that FundMind cannot recover it for me.
                    </label>
                </div>
                <AppButton onClick={onClose} disabled={!isConfirmed || buttonDisabled}>
                    {buttonDisabled ? 'Please save your phrase' : 'Continue'}
                </AppButton>
            </div>
        </Modal>
    );
};


const PinSetupModal: React.FC<{ isOpen: boolean; onClose: () => void; }> = ({ isOpen, onClose }) => {
    const { setUserPin } = useAuth();
    const [pin, setPin] = useState('');
    const [confirmPin, setConfirmPin] = useState('');
    const [error, setError] = useState('');

    const handlePinChange = (e: React.ChangeEvent<HTMLInputElement>, setter: React.Dispatch<React.SetStateAction<string>>) => {
        const { value } = e.target;
        if (/^\d*$/.test(value) && value.length <= 6) {
            setter(value);
        }
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        if (pin.length !== 6) {
            setError('Your PIN must be exactly 6 digits.');
            return;
        }
        if (pin !== confirmPin) {
            setError('The PINs do not match.');
            return;
        }
        setUserPin(pin);
        onClose();
    };

    return (
        <Modal isOpen={isOpen} title="Set Your Security PIN" nonDismissable>
            <form onSubmit={handleSubmit} className="space-y-6">
                <p className="text-medium-text text-center">For added security and quick access, please create a 6-digit PIN.</p>
                {error && <p className="text-accent-negative text-center bg-accent-negative/10 p-2 rounded-lg">{error}</p>}
                <Input 
                    type="password"
                    placeholder="Enter 6-digit PIN"
                    value={pin}
                    onChange={(e) => handlePinChange(e, setPin)}
                    icon={<LockIcon className="w-6 h-6 text-medium-text" />}
                    maxLength={6}
                    required
                />
                 <Input 
                    type="password"
                    placeholder="Confirm 6-digit PIN"
                    value={confirmPin}
                    onChange={(e) => handlePinChange(e, setConfirmPin)}
                    icon={<LockIcon className="w-6 h-6 text-medium-text" />}
                    maxLength={6}
                    required
                />
                <AppButton type="submit" disabled={pin.length !== 6 || confirmPin.length !== 6}>Set PIN</AppButton>
            </form>
        </Modal>
    );
};

const AdminPasswordModal: React.FC<{ 
    isOpen: boolean; 
    onClose: () => void; 
    onSuccess: (stayInSystem: boolean) => void;
}> = ({ isOpen, onClose, onSuccess }) => {
    const { adminPanelPassword } = useAuth();
    const [password, setPassword] = useState('');
    const [stayInSystem, setStayInSystem] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (password === adminPanelPassword) {
            setError('');
            onSuccess(stayInSystem);
            setPassword('');
            setStayInSystem(false);
        } else {
            setError('Incorrect password.');
        }
    };

    const handleClose = () => {
        setError('');
        setPassword('');
        setStayInSystem(false);
        onClose();
    }

    return (
        <Modal isOpen={isOpen} onClose={handleClose} title="Admin Access Required">
            <form onSubmit={handleSubmit} className="space-y-6">
                <p className="text-medium-text">Please enter the admin panel password to continue.</p>
                {error && <p className="text-accent-negative text-center bg-accent-negative/10 p-2 rounded-lg">{error}</p>}
                <Input
                    type="password"
                    placeholder="Admin Password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    icon={<LockIcon className="w-6 h-6 text-medium-text" />}
                    required
                    autoFocus
                />
                <div className="flex items-center px-1">
                    <input
                        id="stay-in-system"
                        name="stay-in-system"
                        type="checkbox"
                        checked={stayInSystem}
                        onChange={(e) => setStayInSystem(e.target.checked)}
                        className="h-4 w-4 rounded border-dark-border bg-dark-space text-accent-primary focus:ring-accent-primary focus:ring-offset-dark-card cursor-pointer"
                    />
                    <label htmlFor="stay-in-system" className="ml-2 block text-sm text-medium-text cursor-pointer">
                        Stay in system for this session
                    </label>
                </div>
                <AppButton type="submit">Enter Admin Panel</AppButton>
            </form>
        </Modal>
    );
};

const KycModal: React.FC<{ isOpen: boolean; onClose: () => void; }> = ({ isOpen, onClose }) => {
    const { currentUser, updateUser } = useAuth();
    const [step, setStep] = useState(1);
    const [isLoading, setIsLoading] = useState(false);
    const [formData, setFormData] = useState({
        fullName: currentUser?.kycData?.fullName || '',
        dob: currentUser?.kycData?.dob || '',
        address: currentUser?.kycData?.address || '',
        idFrontUrl: currentUser?.kycData?.idFrontUrl || '',
        idBackUrl: currentUser?.kycData?.idBackUrl || '',
        livenessVideoUrl: '',
    });

    const [isRecording, setIsRecording] = useState(false);
    const [videoBlobUrl, setVideoBlobUrl] = useState<string | null>(null);
    const videoRef = useRef<HTMLVideoElement>(null);
    const mediaRecorderRef = useRef<MediaRecorder | null>(null);

    const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>, field: 'idFrontUrl' | 'idBackUrl') => {
        if (e.target.files && e.target.files[0]) {
            const file = e.target.files[0];
            const base64 = await fileToBase64(file);
            setFormData(prev => ({ ...prev, [field]: base64 }));
        }
    };

    const startCamera = async () => {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
            if (videoRef.current) {
                videoRef.current.srcObject = stream;
            }
            mediaRecorderRef.current = new MediaRecorder(stream);
            mediaRecorderRef.current.ondataavailable = (event) => {
                const blob = new Blob([event.data], { type: 'video/webm' });
                const reader = new FileReader();
                reader.readAsDataURL(blob);
                reader.onloadend = () => {
                    setFormData(prev => ({ ...prev, livenessVideoUrl: reader.result as string }));
                    setVideoBlobUrl(URL.createObjectURL(blob));
                };
            };
        } catch (err) {
            console.error("Error accessing camera:", err);
            alert("Could not access camera. Please check permissions.");
        }
    };

    const stopCamera = () => {
        if (videoRef.current && videoRef.current.srcObject) {
            const stream = videoRef.current.srcObject as MediaStream;
            stream.getTracks().forEach(track => track.stop());
            videoRef.current.srcObject = null;
        }
    };

    const handleStartRecording = () => {
        if (mediaRecorderRef.current) {
            setIsRecording(true);
            setVideoBlobUrl(null);
            setFormData(prev => ({ ...prev, livenessVideoUrl: '' }));
            mediaRecorderRef.current.start();
            setTimeout(() => {
                handleStopRecording();
            }, 5000); // Record for 5 seconds
        }
    };

    const handleStopRecording = () => {
        if (mediaRecorderRef.current && mediaRecorderRef.current.state === 'recording') {
            mediaRecorderRef.current.stop();
            setIsRecording(false);
        }
    };
    
    useEffect(() => {
        if (isOpen && step === 3) {
            startCamera();
        } else {
            stopCamera();
        }
        return () => stopCamera();
    }, [isOpen, step]);


    const handleSubmit = async () => {
        if (!currentUser) return;
        setIsLoading(true);
        // Simulate network delay
        await new Promise(resolve => setTimeout(() => resolve(null), 1500));
        updateUser({
            ...currentUser,
            kycStatus: KycStatus.Pending,
            kycData: { ...formData }
        });
        setIsLoading(false);
        onClose();
        alert("KYC documents submitted successfully. Your application is now under review.");
    };

    const renderStep = () => {
        switch (step) {
            case 1: return (
                <div className="space-y-4">
                    <p className="text-medium-text">Please provide your legal information as it appears on your official documents.</p>
                    <Input type="text" placeholder="Full Legal Name" value={formData.fullName} onChange={e => setFormData({...formData, fullName: e.target.value})} required />
                    <Input type="date" placeholder="Date of Birth" value={formData.dob} onChange={e => setFormData({...formData, dob: e.target.value})} required />
                    <Input type="text" placeholder="Full Address" value={formData.address} onChange={e => setFormData({...formData, address: e.target.value})} required />
                    <AppButton onClick={() => setStep(2)} disabled={!formData.fullName || !formData.dob || !formData.address}>Next</AppButton>
                </div>
            );
            case 2: return (
                <div className="space-y-4">
                    <p className="text-medium-text">Upload clear, readable photos of your government-issued ID.</p>
                    <div>
                        <label className="text-sm text-medium-text block mb-2 px-2">ID Front</label>
                        <Input type="file" accept="image/*" onChange={e => handleFileChange(e, 'idFrontUrl')} className="file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-accent-primary file:text-dark-space hover:file:bg-opacity-80"/>
                        {formData.idFrontUrl && <img src={formData.idFrontUrl} alt="ID Front Preview" className="mt-2 rounded-lg max-h-40 mx-auto" />}
                    </div>
                     <div>
                        <label className="text-sm text-medium-text block mb-2 px-2">ID Back</label>
                        <Input type="file" accept="image/*" onChange={e => handleFileChange(e, 'idBackUrl')} className="file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-accent-primary file:text-dark-space hover:file:bg-opacity-80"/>
                        {formData.idBackUrl && <img src={formData.idBackUrl} alt="ID Back Preview" className="mt-2 rounded-lg max-h-40 mx-auto" />}
                    </div>
                    <div className="flex gap-4 pt-2">
                        <button onClick={() => setStep(1)} className="w-full bg-dark-border text-light-text font-bold py-3 px-6 transition-colors hover:bg-white/20 rounded-lg">Back</button>
                        <AppButton onClick={() => setStep(3)} disabled={!formData.idFrontUrl || !formData.idBackUrl}>Next</AppButton>
                    </div>
                </div>
            );
            case 3: return (
                <div className="space-y-4 text-center">
                    <p className="text-medium-text">To verify your identity, please record a short video of your face.</p>
                    <div className="bg-dark-space rounded-lg overflow-hidden aspect-video w-full max-w-sm mx-auto flex items-center justify-center">
                        {videoBlobUrl ? (
                            <video src={videoBlobUrl} controls className="w-full h-full" />
                        ) : (
                            <video ref={videoRef} autoPlay playsInline muted className="w-full h-full object-cover" />
                        )}
                    </div>
                     {isRecording && <p className="text-accent-primary font-semibold animate-pulse">Recording... Look at the camera.</p>}
                    
                    <div className="flex flex-col sm:flex-row gap-4 pt-2">
                         <button onClick={() => setStep(2)} className="w-full bg-dark-border text-light-text font-bold py-3 px-6 transition-colors hover:bg-white/20 rounded-lg">Back</button>
                        {videoBlobUrl ? (
                            <AppButton onClick={() => { setVideoBlobUrl(null); startCamera(); }}>Re-record</AppButton>
                        ) : (
                            <AppButton onClick={handleStartRecording} disabled={isRecording}>
                                {isRecording ? <Spinner className="w-6 h-6 mx-auto" /> : 'Start Recording'}
                            </AppButton>
                        )}
                    </div>
                    <AppButton onClick={handleSubmit} disabled={!formData.livenessVideoUrl || isRecording || isLoading}>
                        {isLoading ? <Spinner className="w-6 h-6 mx-auto"/> : "Submit Verification"}
                    </AppButton>
                </div>
            );
        }
    };

    return (
        <Modal isOpen={isOpen} onClose={onClose} title={`Identity Verification - Step ${step} of 3`} size="lg">
            {renderStep()}
        </Modal>
    );
};


// --- PAGES ---

const Greeting: React.FC<{ username?: string }> = ({ username }) => {
    const [timeOfDay, setTimeOfDay] = useState('');

    useEffect(() => {
        const hour = new Date().getHours();
        if (hour < 12) setTimeOfDay('Morning');
        else if (hour < 18) setTimeOfDay('Afternoon');
        else setTimeOfDay('Evening');
    }, []);

    return (
        <div className="mb-6">
            <h1 className="text-3xl sm:text-4xl font-bold text-light-text">
                Good {timeOfDay}, {username || 'User'}.
            </h1>
        </div>
    );
};

const PortfolioChart: React.FC<{ selectedAssetId: string, assets: Asset[] }> = React.memo(({ selectedAssetId, assets }) => {
    const [chartData, setChartData] = useState<[number, number][]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [timePeriod, setTimePeriod] = useState(30);
    const debounceTimeoutRef = useRef<NodeJS.Timeout | null>(null);

    useEffect(() => {
        if (debounceTimeoutRef.current) {
            clearTimeout(debounceTimeoutRef.current);
        }

        const controller = new AbortController();
        const signal = controller.signal;

        const fetchChartData = async (signal: AbortSignal) => {
            const selectedAsset = assets.find(a => a.id === selectedAssetId);

            if (!selectedAsset) {
                setChartData([]);
                setIsLoading(false);
                return;
            }

            setIsLoading(true);

            // Handle stablecoin case
            if (selectedAsset.symbol === 'USDT') {
                const now = Date.now();
                const fakeData = Array.from({ length: timePeriod }, (_, i) => {
                    const timestamp = now - (timePeriod - 1 - i) * 24 * 60 * 60 * 1000;
                    return [timestamp, 1.00] as [number, number];
                });
                setChartData(fakeData);
                setIsLoading(false);
                return;
            }
            
            try {
                const symbol = `${selectedAsset.symbol.toUpperCase()}USDT`;
                const interval = '1d'; // Daily data
                const response = await fetch(`https://api.binance.com/api/v3/klines?symbol=${symbol}&interval=${interval}&limit=${timePeriod}`, { signal });

                if (!response.ok) {
                    throw new Error(`Failed to fetch chart data from Binance for ${symbol}`);
                }
                
                const data = await response.json();

                if (signal.aborted) return;
                
                if (Array.isArray(data)) {
                    // Binance kline format: [timestamp, open, high, low, close, ...]
                    const formattedData = data.map((kline: (string | number)[]) => [
                        Number(kline[0]),       // timestamp
                        parseFloat(String(kline[4])) // close price
                    ] as [number, number]);
                    setChartData(formattedData);
                } else {
                     setChartData([]);
                }

            } catch (error) {
                if (error instanceof Error && error.name !== 'AbortError') {
                    console.error(`Chart data fetch error for asset '${selectedAssetId}':`, error);
                    if (!signal.aborted) {
                        setChartData([]);
                    }
                }
            } finally {
                if (!signal.aborted) {
                    setIsLoading(false);
                }
            }
        };
        
        debounceTimeoutRef.current = setTimeout(() => {
             fetchChartData(signal);
        }, 300);

        return () => {
            if (debounceTimeoutRef.current) {
                clearTimeout(debounceTimeoutRef.current);
            }
            controller.abort();
        };
    }, [timePeriod, selectedAssetId, assets]);

    const SvgChart = () => {
        if (chartData.length < 2) return <div className="text-center text-medium-text">Not enough data to display chart.</div>;

        const width = 500; const height = 150;
        const prices = chartData.map(p => p[1]);
        const timestamps = chartData.map(p => p[0]);
        const minPrice = Math.min(...prices);
        const maxPrice = Math.max(...prices);
        const minTime = Math.min(...timestamps);
        const maxTime = Math.max(...timestamps);

        const priceRange = maxPrice - minPrice;

        const getX = (time: number) => ((time - minTime) / (maxTime - minTime)) * width;
        const getY = (price: number) => {
            if (priceRange === 0) return height / 2;
            return height - ((price - minPrice) / priceRange) * height;
        };

        const path = chartData.map((p, i) => {
            const x = getX(p[0]); const y = getY(p[1]);
            return i === 0 ? `M ${x} ${y}` : `L ${x} ${y}`;
        }).join(' ');

        const areaPath = `${path} V ${height} L ${getX(chartData[0][0])} ${height} Z`;

        const isPositive = chartData[chartData.length - 1][1] >= chartData[0][1];
        const strokeColor = isPositive ? 'rgb(var(--accent-primary))' : 'rgb(var(--accent-negative))';
        const filterId = "chart-glow-filter";
        const positiveGradientId = "gradient-positive";
        const negativeGradientId = "gradient-negative";

        return (
            <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-full" preserveAspectRatio="xMidYMid meet" style={{ overflow: 'visible' }}>
                <defs>
                    <filter id={filterId}>
                        <feGaussianBlur stdDeviation="6" result="coloredBlur" />
                    </filter>
                    <linearGradient id={positiveGradientId} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="rgb(var(--accent-primary))" stopOpacity={0.4} />
                        <stop offset="100%" stopColor="rgb(var(--accent-primary))" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id={negativeGradientId} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="rgb(var(--accent-negative))" stopOpacity={0.4} />
                        <stop offset="100%" stopColor="rgb(var(--accent-negative))" stopOpacity={0} />
                    </linearGradient>
                </defs>
                <path
                    d={areaPath}
                    fill={isPositive ? `url(#${positiveGradientId})` : `url(#${negativeGradientId})`}
                />
                <path 
                    d={path} 
                    fill="none" 
                    stroke={strokeColor} 
                    strokeWidth="12"
                    strokeLinecap="round" 
                    strokeLinejoin="round" 
                    style={{ opacity: 0.25, filter: `url(#${filterId})` }} 
                />
                <path 
                    d={path} 
                    fill="none" 
                    stroke={strokeColor} 
                    strokeWidth="2" 
                    strokeLinecap="round" 
                    strokeLinejoin="round"
                />
            </svg>
        );
    };
    
    const timePeriods = [ { label: '1W', days: 7 }, { label: '1M', days: 30 }, { label: '3M', days: 90 }, { label: '6M', days: 180 }, { label: '1Y', days: 365 }];

    return (
        <div className="w-full">
            <div className="h-40 flex items-center justify-center">
                {isLoading ? <Spinner className="w-8 h-8"/> : <SvgChart />}
            </div>
            <div className="flex justify-center gap-2 mt-4">
                {timePeriods.map(({label, days}) => (
                    <button key={label} onClick={() => setTimePeriod(days)} className={`px-4 py-1.5 text-sm font-semibold rounded-lg transition-colors ${timePeriod === days ? 'bg-accent-primary text-dark-space' : 'bg-dark-space/50 hover:bg-white/10'}`}>
                        {label}
                    </button>
                ))}
            </div>
        </div>
    );
});

const Dashboard: React.FC<{ 
    assets: Asset[],
    walletAssets: WalletAsset[], 
    totalValue: number, 
    onActionClick: (action: 'send' | 'receive' | 'buy' | 'sell' | 'swap') => void,
    setPage: (page: string) => void
}> = ({ assets, walletAssets, totalValue, onActionClick, setPage }) => {
    const { currentUser } = useAuth();
    const [selectedAssetIdForChart, setSelectedAssetIdForChart] = useState<string>('');

    useEffect(() => {
        if (walletAssets.length > 0 && !selectedAssetIdForChart) {
            const ownedAssets = walletAssets.filter(a => a.balance > 0);
            if (ownedAssets.length > 0) {
                const highestValueAsset = ownedAssets.reduce((max, asset) => 
                    (asset.balance * asset.price) > (max.balance * max.price) ? asset : max
                );
                setSelectedAssetIdForChart(highestValueAsset.id);
            } else {
                setSelectedAssetIdForChart(walletAssets[0].id); // Default to the first asset if none are owned
            }
        }
    }, [walletAssets, selectedAssetIdForChart]);

    const portfolio24hChange = useMemo(() => {
        let currentTotal = 0;
        let previousTotal = 0;

        walletAssets.forEach(asset => {
            const currentValue = asset.balance * asset.price;
            currentTotal += currentValue;
            if (asset.price > 0 && asset.change24h) {
                const previousPrice = asset.price / (1 + (asset.change24h / 100));
                previousTotal += asset.balance * previousPrice;
            } else {
                previousTotal += currentValue; // No change data, assume flat
            }
        });
        
        if (previousTotal === 0) return { change: 0, percent: 0 };
        const change = currentTotal - previousTotal;
        const percent = (change / previousTotal) * 100;
        return { change, percent };
    }, [walletAssets]);

    const displayedAssets = useMemo(() => {
        return walletAssets.filter(asset => currentUser?.dashboardAssetVisibility?.[asset.id] ?? true);
    }, [walletAssets, currentUser]);

    const ActionButton = ({ icon: Icon, label, action }: { icon: React.FC<any>, label: string, action: () => void }) => (
        <button onClick={action} className="flex flex-col items-center justify-center gap-2 text-light-text group">
            <div className="w-14 h-14 bg-white/10 backdrop-blur-md ring-1 ring-white/20 rounded-full flex items-center justify-center transition-all duration-300 group-hover:bg-white/20 group-hover:scale-110">
                <Icon className="w-6 h-6"/>
            </div>
            <span className="text-sm font-semibold">{label}</span>
        </button>
    );

    return (
        <PageContainer>
            <div className="flex flex-col items-center gap-8 pb-24">
                {/* Balance Section */}
                <div className="text-center">
                    <p className="text-medium-text text-lg">Total Portfolio Value</p>
                    <p className="text-4xl font-semibold text-light-text font-mono tracking-tight">{formatCurrency(totalValue)}</p>
                    <div className={`mt-1 flex items-center justify-center gap-2 font-medium text-base ${portfolio24hChange.change >= 0 ? 'text-accent-primary' : 'text-accent-negative'}`}>
                        {portfolio24hChange.change >= 0 ? <ArrowUpIcon className="w-4 h-4" /> : <ArrowDownIcon className="w-4 h-4" />}
                        <span>{formatCurrency(Math.abs(portfolio24hChange.change))} ({formatPercent(Math.abs(portfolio24hChange.percent))}) 24h</span>
                    </div>
                </div>

                {/* Action Buttons Section */}
                 <div className="flex justify-around items-center w-full max-w-md">
                    <ActionButton icon={SendIcon} label="Send" action={() => onActionClick('send')} />
                    <ActionButton icon={ReceiveIcon} label="Receive" action={() => onActionClick('receive')} />
                    <ActionButton icon={BuyIcon} label="Buy" action={() => onActionClick('buy')} />
                    <ActionButton icon={SellIcon} label="Sell" action={() => onActionClick('sell')} />
                </div>

                {/* Chart Section */}
                <div className="w-full max-w-4xl">
                    <PortfolioChart selectedAssetId={selectedAssetIdForChart} assets={assets} />
                </div>

                {/* Assets List Section */}
                 <div className="w-full bg-dark-card p-4 sm:p-6 backdrop-blur-xl rounded-2xl max-w-4xl">
                    <div className="space-y-3 max-h-96 overflow-y-auto pr-2">
                        {displayedAssets.length > 0 ? displayedAssets.map(asset => (
                            <div 
                                key={asset.id} 
                                onClick={() => setSelectedAssetIdForChart(asset.id)}
                                className={`flex justify-between items-center p-3 rounded-xl hover:bg-dark-space/50 transition-all duration-300 group cursor-pointer ${
                                    selectedAssetIdForChart === asset.id ? 'bg-dark-space ring-2 ring-accent-primary/50' : ''
                                }`}
                            >
                                <div className="flex items-center gap-4">
                                    <div className="relative">
                                        {asset.icon ? <img src={asset.icon} alt={asset.name} className="w-10 h-10 rounded-full" /> : <GenericAssetIcon className="w-10 h-10 text-medium-text" />}
                                    </div>
                                    <div>
                                        <p className="font-bold">{asset.name}</p>
                                        <p className="text-medium-text text-sm">{asset.symbol}</p>
                                    </div>
                                </div>
                                <div className="text-right">
                                     <p className="font-bold font-mono">{formatCrypto(asset.balance)}</p>
                                     <p className="text-medium-text text-sm font-mono">{formatCurrency(asset.balance * asset.price)}</p>
                                </div>
                            </div>
                        )) : (
                            <p className="text-center p-8 text-medium-text">Your assets will appear here.</p>
                        )}
                    </div>
                </div>
            </div>
        </PageContainer>
    );
};

const Transactions: React.FC<{ assets: Asset[] }> = ({ assets }) => {
    const { currentUser } = useAuth();
    const transactions = currentUser?.transactions?.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()) || [];
    const getAssetSymbol = (assetId: string) => assets.find(a => a.id === assetId)?.symbol || 'N/A';
    const getStatusChip = (status: TransactionStatus) => {
        const colorMap: Record<TransactionStatus, string> = {
            [TransactionStatus.Completed]: 'bg-accent-primary/20 text-accent-primary',
            [TransactionStatus.Processing]: 'bg-accent-info/20 text-accent-info',
            [TransactionStatus.Failed]: 'bg-accent-negative/20 text-accent-negative',
            [TransactionStatus.Canceled]: 'bg-accent-warning/20 text-accent-warning',
        };
        return <span className={`px-3 py-1 text-xs font-semibold rounded-full ${colorMap[status]}`}>{status}</span>;
    };
    return (
        <PageContainer>
             
             <div className="bg-dark-card overflow-hidden backdrop-blur-xl rounded-2xl">
                {/* Mobile Card View */}
                <div className="md:hidden">
                    {transactions.length > 0 ? (
                        <div className="divide-y divide-dark-border">
                            {transactions.map(tx => (
                                <div key={tx.id} className="p-4 space-y-2">
                                    <div className="flex justify-between items-start">
                                        <div>
                                            <p className="font-bold text-lg">{tx.type} {getAssetSymbol(tx.assetId)}</p>
                                            <p className="text-sm text-medium-text">{new Date(tx.timestamp).toLocaleString('en-US')}</p>
                                        </div>
                                        {getStatusChip(tx.status)}
                                    </div>
                                    <div className="flex justify-between items-end pt-2">
                                        <div>
                                            <p className="text-medium-text text-sm">Amount</p>
                                            <p className="font-semibold font-mono">{formatCrypto(tx.amount)}</p>
                                        </div>
                                        <div className="text-right">
                                            <p className="text-medium-text text-sm">Value</p>
                                            <p className="font-semibold font-mono">{formatCurrency(tx.usdValue)}</p>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <p className="text-center p-8 text-medium-text">No transactions yet.</p>
                    )}
                </div>

                {/* Desktop Table View */}
                <div className="hidden md:block overflow-x-auto">
                    <table className="w-full text-left">
                        <thead className="bg-dark-space/50">
                            <tr>{['Date', 'Type', 'Asset', 'Amount', 'Value (USD)', 'Status'].map(h => <th key={h} className="p-4 font-semibold text-medium-text uppercase text-sm">{h}</th>)}</tr>
                        </thead>
                        <tbody>
                            {transactions.length > 0 ? transactions.map(tx => (
                                <tr key={tx.id} className="border-t border-dark-border">
                                    <td className="p-4 whitespace-nowrap">{new Date(tx.timestamp).toLocaleString('en-US')}</td><td className="p-4 font-semibold">{tx.type}</td>
                                    <td className="p-4">{getAssetSymbol(tx.assetId)}</td><td className="p-4 font-mono">{formatCrypto(tx.amount)}</td>
                                    <td className="p-4 font-mono">{formatCurrency(tx.usdValue)}</td><td className="p-4">{getStatusChip(tx.status)}</td>
                                </tr>
                            )) : (<tr><td colSpan={6} className="text-center p-8 text-medium-text">No transactions yet.</td></tr>)}
                        </tbody>
                    </table>
                </div>
            </div>
        </PageContainer>
    );
};

const UserAccountSettings: React.FC<{ walletAssets: WalletAsset[] }> = ({ walletAssets }) => {
    const { currentUser, updateUserCredentials, updateUser } = useAuth();
    const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string; context: string } | null>(null);

    const [usernameData, setUsernameData] = useState({ newUsername: '', password: '' });
    const [emailData, setEmailData] = useState({ newEmail: '', password: '' });
    const [passwordData, setPasswordData] = useState({ currentPassword: '', newPassword: '', confirmPassword: '' });
    const [pinData, setPinData] = useState({ password: '', newPin: '', confirmPin: '' });

    const handleAssetVisibilityToggle = (assetId: string, isVisible: boolean) => {
        if (!currentUser) return;
        const updatedVisibility = {
            ...(currentUser.dashboardAssetVisibility || {}),
            [assetId]: isVisible,
        };
        updateUser({ ...currentUser, dashboardAssetVisibility: updatedVisibility });
    };

    const handleFormSubmit = async (
        e: React.FormEvent,
        type: 'email' | 'password' | 'pin' | 'username',
        currentPasswordForVerification: string,
        newValue: string,
        confirmValue?: string
    ) => {
        e.preventDefault();
        setMessage(null);

        if (confirmValue !== undefined && newValue !== confirmValue) {
            setMessage({ type: 'error', text: `New ${type}s do not match.`, context: type });
            return;
        }
        
        if (type === 'pin' && (newValue.length !== 6 || !/^\d+$/.test(newValue))) {
             setMessage({ type: 'error', text: 'PIN must be exactly 6 digits.', context: type });
             return;
        }

        const result = updateUserCredentials(type, currentPasswordForVerification, newValue);

        if (result.success) {
            setMessage({ type: 'success', text: result.message, context: type });
            // Reset relevant form
            if (type === 'username') setUsernameData({ newUsername: '', password: '' });
            if (type === 'email') setEmailData({ newEmail: '', password: '' });
            if (type === 'password') setPasswordData({ currentPassword: '', newPassword: '', confirmPassword: '' });
            if (type === 'pin') setPinData({ password: '', newPin: '', confirmPin: '' });
        } else {
            setMessage({ type: 'error', text: result.message, context: type });
        }
    };

    const MessageDisplay = ({ context }: { context: string }) => {
        if (message && message.context === context) {
            return (
                <div className={`p-3 rounded-lg mt-4 text-center text-sm ${message.type === 'success' ? 'bg-accent-primary/20 text-accent-primary' : 'bg-accent-negative/20 text-accent-negative'} rounded-lg`}>
                    {message.text}
                </div>
            );
        }
        return null;
    };

    return (
        <div className="bg-dark-card p-6 space-y-8 backdrop-blur-xl rounded-2xl">
            <h2 className="text-2xl font-bold">Account Settings</h2>
            
            {/* Dashboard Assets */}
            <div className="space-y-4">
                <h3 className="text-lg font-semibold text-light-text">Dashboard Assets</h3>
                <p className="text-sm text-medium-text">Choose which assets appear on your main dashboard.</p>
                <div className="space-y-2 max-h-60 overflow-y-auto">
                    {walletAssets.map(asset => (
                        <div key={asset.id} className="flex items-center justify-between bg-dark-space/50 p-3 rounded-lg">
                            <span className="font-semibold">{asset.name} ({asset.symbol})</span>
                            <label className="relative inline-flex items-center cursor-pointer">
                                <input 
                                    type="checkbox" 
                                    className="sr-only peer"
                                    checked={currentUser?.dashboardAssetVisibility?.[asset.id] ?? true}
                                    onChange={(e) => handleAssetVisibilityToggle(asset.id, e.target.checked)}
                                />
                                <div className="w-11 h-6 bg-dark-border rounded-full peer peer-focus:ring-2 peer-focus:ring-accent-primary/50 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-0.5 after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-accent-primary"></div>
                            </label>
                        </div>
                    ))}
                </div>
            </div>

            <hr className="border-dark-border" />

            {/* Change Username */}
            <form onSubmit={e => handleFormSubmit(e, 'username', usernameData.password, usernameData.newUsername)} className="space-y-4">
                <div>
                    <h3 className="text-lg font-semibold text-light-text mb-2">Change Nickname</h3>
                    <div className="space-y-4">
                        <Input type="text" placeholder="New Nickname" value={usernameData.newUsername} onChange={e => setUsernameData({...usernameData, newUsername: e.target.value})} icon={<ProfileIcon className="w-6 h-6 text-medium-text" />} required />
                        <Input type="password" placeholder="Current Password for Verification" value={usernameData.password} onChange={e => setUsernameData({...usernameData, password: e.target.value})} icon={<LockIcon className="w-6 h-6 text-medium-text" />} required />
                    </div>
                </div>
                <AppButton type="submit" className="max-w-xs">Update Nickname</AppButton>
                <MessageDisplay context="username" />
            </form>

            <hr className="border-dark-border" />
            
            {/* Change Email */}
            <form onSubmit={e => handleFormSubmit(e, 'email', emailData.password, emailData.newEmail)} className="space-y-4">
                <div>
                    <h3 className="text-lg font-semibold text-light-text mb-2">Change Email Address</h3>
                    <div className="space-y-4">
                        <Input type="email" placeholder="New Email Address" value={emailData.newEmail} onChange={e => setEmailData({...emailData, newEmail: e.target.value})} icon={<EmailIcon className="w-6 h-6 text-medium-text" />} required />
                        <Input type="password" placeholder="Current Password for Verification" value={emailData.password} onChange={e => setEmailData({...emailData, password: e.target.value})} icon={<LockIcon className="w-6 h-6 text-medium-text" />} required />
                    </div>
                </div>
                <AppButton type="submit" className="max-w-xs">Update Email</AppButton>
                <MessageDisplay context="email" />
            </form>

            <hr className="border-dark-border" />
            
            {/* Change Password */}
            <form onSubmit={e => handleFormSubmit(e, 'password', passwordData.currentPassword, passwordData.newPassword, passwordData.confirmPassword)} className="space-y-4">
                 <div>
                    <h3 className="text-lg font-semibold text-light-text mb-2">Change Password</h3>
                    <div className="space-y-4">
                        <Input type="password" placeholder="Current Password" value={passwordData.currentPassword} onChange={e => setPasswordData({...passwordData, currentPassword: e.target.value})} icon={<LockIcon className="w-6 h-6 text-medium-text" />} required />
                        <Input type="password" placeholder="New Password" value={passwordData.newPassword} onChange={e => setPasswordData({...passwordData, newPassword: e.target.value})} icon={<LockIcon className="w-6 h-6 text-medium-text" />} required />
                        <PasswordStrengthMeter password={passwordData.newPassword} />
                        <Input type="password" placeholder="Confirm New Password" value={passwordData.confirmPassword} onChange={e => setPasswordData({...passwordData, confirmPassword: e.target.value})} icon={<LockIcon className="w-6 h-6 text-medium-text" />} required />
                    </div>
                </div>
                <AppButton type="submit" className="max-w-xs">Update Password</AppButton>
                <MessageDisplay context="password" />
            </form>

             <hr className="border-dark-border" />

            {/* Change PIN */}
            <form onSubmit={e => handleFormSubmit(e, 'pin', pinData.password, pinData.newPin, pinData.confirmPin)} className="space-y-4">
                 <div>
                    <h3 className="text-lg font-semibold text-light-text mb-2">Change 6-Digit PIN</h3>
                    <div className="space-y-4">
                        <Input type="password" placeholder="Current Password for Verification" value={pinData.password} onChange={e => setPinData({...pinData, password: e.target.value})} icon={<LockIcon className="w-6 h-6 text-medium-text" />} required />
                        <Input type="password" placeholder="New 6-Digit PIN" value={pinData.newPin} onChange={e => /^\d*$/.test(e.target.value) && setPinData({...pinData, newPin: e.target.value})} maxLength={6} icon={<LockIcon className="w-6 h-6 text-medium-text" />} required />
                        <Input type="password" placeholder="Confirm New PIN" value={pinData.confirmPin} onChange={e => /^\d*$/.test(e.target.value) && setPinData({...pinData, confirmPin: e.target.value})} maxLength={6} icon={<LockIcon className="w-6 h-6 text-medium-text" />} required />
                    </div>
                </div>
                <AppButton type="submit" className="max-w-xs">Update PIN</AppButton>
                 <MessageDisplay context="pin" />
            </form>

            <hr className="border-dark-border" />

            <div className="space-y-2">
                <h3 className="text-lg font-semibold text-light-text">Your Account Recovery Phrase</h3>
                <p className="text-sm text-medium-text">
                    This is the master key to your FundMind account. Keep it safe and never share it.
                </p>
                <div className="font-mono bg-dark-space p-4 text-center text-accent-primary tracking-wider rounded-xl">
                    {currentUser?.appRecoveryPhrase}
                </div>
            </div>
        </div>
    );
};

const Profile: React.FC<{ walletAssets: WalletAsset[] }> = ({ walletAssets }) => {
    const { currentUser } = useAuth();
    const [isKycModalOpen, setIsKycModalOpen] = useState(false);
    if (!currentUser) return null;

    const KycStatusDisplay = () => {
        let statusText, statusColor, buttonText;

        switch (currentUser.kycStatus) {
            case KycStatus.Verified:
                statusText = "Your identity is verified.";
                statusColor = "bg-accent-primary/20 text-accent-primary";
                buttonText = "Verified";
                break;
            case KycStatus.Pending:
                statusText = "Your documents are under review.";
                statusColor = "bg-accent-warning/20 text-accent-warning";
                buttonText = "Verification Pending";
                break;
            case KycStatus.Rejected:
                statusText = "Your verification was rejected. Please resubmit your documents.";
                statusColor = "bg-accent-negative/20 text-accent-negative";
                buttonText = "Resubmit Verification";
                break;
            default: // NotStarted
                statusText = "To access all features, please complete identity verification.";
                statusColor = "bg-gray-500/20 text-gray-400";
                buttonText = "Start Verification";
                break;
        }

        return (
            <div className="bg-dark-card p-6 backdrop-blur-xl rounded-2xl">
                <h2 className="text-xl font-bold mb-4">Identity Verification (KYC)</h2>
                <div className={`p-4 rounded-lg flex items-center justify-between ${statusColor}`}>
                    <p className="font-semibold">{statusText}</p>
                    <button 
                        onClick={() => setIsKycModalOpen(true)}
                        className="bg-accent-primary text-dark-space font-bold py-2 px-4 transition-all duration-300 transform hover:scale-105 active:scale-100 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg"
                        disabled={currentUser.kycStatus === KycStatus.Pending || currentUser.kycStatus === KycStatus.Verified}
                    >
                        {buttonText}
                    </button>
                </div>
            </div>
        );
    };

    return (
        <PageContainer>
            <div className="space-y-6">
                <Greeting username={currentUser.username} />
                <KycStatusDisplay />
                <UserAccountSettings walletAssets={walletAssets} />
            </div>
            <KycModal isOpen={isKycModalOpen} onClose={() => setIsKycModalOpen(false)} />
        </PageContainer>
    );
};

const Chat: React.FC = () => {
    const { currentUser } = useAuth();
    const [messages, setMessages] = useState<ChatMessage[]>([
        { sender: 'ai', text: `Hi ${currentUser?.username || 'there'}! I'm Mindy, your AI assistant. How can I help you today?` }
    ]);
    const [input, setInput] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const messagesEndRef = useRef<HTMLDivElement>(null);

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };

    useEffect(scrollToBottom, [messages]);

    const handleSend = async () => {
        if (!input.trim() || isLoading) return;
        
        const userMessage: ChatMessage = { sender: 'user', text: input };
        const newMessages = [...messages, userMessage];
        setMessages(newMessages);
        setInput('');
        setIsLoading(true);

        try {
            const aiResponseText = await getAiResponse(newMessages);
            const aiMessage: ChatMessage = { sender: 'ai', text: aiResponseText };
            setMessages(prev => [...prev, aiMessage]);
        } catch (error) {
            console.error(error);
            const errorMessage: ChatMessage = { sender: 'ai', text: "Sorry, I'm having trouble connecting right now." };
            setMessages(prev => [...prev, errorMessage]);
        } finally {
            setIsLoading(false);
        }
    };

    return (
         <PageContainer>
            <div className="bg-dark-card h-[calc(100vh-12rem)] md:h-[calc(100vh-8rem)] flex flex-col backdrop-blur-xl rounded-2xl">
                <div className="flex-grow p-6 overflow-y-auto space-y-6">
                    {messages.map((msg, index) => (
                        <div key={index} className={`flex items-end gap-3 ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
                            {msg.sender === 'ai' && (
                                <div className="w-10 h-10 rounded-full bg-gradient-to-br from-accent-special to-accent-primary flex-shrink-0 flex items-center justify-center organic-pebble">
                                    <ChatIcon className="w-6 h-6 text-dark-space"/>
                                </div>
                            )}
                            <div className={`max-w-xs md:max-w-md lg:max-w-lg p-4 rounded-3xl ${msg.sender === 'user' ? 'bg-accent-primary text-dark-space rounded-br-lg' : 'bg-dark-space/50 text-light-text rounded-bl-lg'}`}>
                                <p style={{ whiteSpace: 'pre-wrap' }}>{msg.text}</p>
                            </div>
                        </div>
                    ))}
                    {isLoading && (
                        <div className="flex items-end gap-3 justify-start">
                             <div className="w-10 h-10 rounded-full bg-gradient-to-br from-accent-special to-accent-primary flex-shrink-0 flex items-center justify-center organic-pebble">
                                <ChatIcon className="w-6 h-6 text-dark-space"/>
                            </div>
                            <div className="max-w-xs md:max-w-md lg:max-w-lg p-4 rounded-3xl bg-dark-space/50 text-light-text rounded-bl-lg flex items-center gap-2">
                                <Spinner className="w-5 h-5" /><span>Thinking...</span>
                            </div>
                        </div>
                    )}
                    <div ref={messagesEndRef} />
                </div>
                <div className="p-4 border-t-2 border-dark-border">
                    <div className="flex gap-4">
                        <Input 
                            type="text" 
                            placeholder="Ask Mindy anything..." 
                            value={input}
                            onChange={e => setInput(e.target.value)}
                            onKeyPress={e => e.key === 'Enter' && handleSend()}
                        />
                        <button onClick={handleSend} disabled={isLoading || !input.trim()} className="bg-accent-primary p-3 rounded-xl disabled:opacity-50 transition-transform transform hover:scale-105 active:scale-100 rounded-lg">
                            <SendIcon className="w-6 h-6 text-dark-space -rotate-90"/>
                        </button>
                    </div>
                </div>
            </div>
        </PageContainer>
    );
};

const Markets: React.FC<{ assets: Asset[] }> = ({ assets }) => {
    return (
        <PageContainer>
            <div className="bg-dark-card overflow-hidden backdrop-blur-xl rounded-2xl">
                 <div className="p-6">
                    <h2 className="text-2xl font-bold text-light-text">Market Overview</h2>
                    <p className="text-medium-text">Live prices from global markets.</p>
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead className="bg-dark-space/50">
                            <tr>
                                <th className="p-4 font-semibold text-medium-text uppercase text-sm">Asset</th>
                                <th className="p-4 font-semibold text-medium-text uppercase text-sm text-right">Price</th>
                                <th className="p-4 font-semibold text-medium-text uppercase text-sm text-right">24h Change</th>
                            </tr>
                        </thead>
                         <tbody>
                             {assets.length > 0 ? assets.map(asset => (
                                <tr key={asset.id} className="border-t border-dark-border">
                                    <td className="p-4">
                                         <div className="flex items-center gap-4">
                                            {asset.icon ? <img src={asset.icon} alt={asset.name} className="w-10 h-10 rounded-full" /> : <GenericAssetIcon className="w-10 h-10 text-medium-text" />}
                                            <div>
                                                <p className="font-bold">{asset.name}</p>
                                                <p className="text-medium-text text-sm">{asset.symbol}</p>
                                            </div>
                                        </div>
                                    </td>
                                    <td className="p-4 text-right font-mono font-semibold">{formatCurrency(asset.price)}</td>
                                    <td className={`p-4 text-right font-mono font-semibold ${asset.change24h >= 0 ? 'text-accent-primary' : 'text-accent-negative'}`}>{formatPercent(asset.change24h)}</td>
                                </tr>
                             )) : <tr><td colSpan={3} className="text-center p-8 text-medium-text">No market data available.</td></tr>}
                        </tbody>
                    </table>
                </div>
            </div>
        </PageContainer>
    );
};

const InvestmentPlatform: React.FC<{ walletAssets: WalletAsset[] }> = ({ walletAssets }) => {
    const { currentUser, stakes, createStake } = useAuth();
    const [selectedRisk, setSelectedRisk] = useState<RiskLevel>('Medium');
    const [stakeAmount, setStakeAmount] = useState('');
    const [stakePeriod, setStakePeriod] = useState(6);
    const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
    
    const usdtBalance = walletAssets.find(a => a.symbol === 'USDT')?.balance || 0;
    const estimatedInterest = parseFloat(stakeAmount) * RISK_LEVELS[selectedRisk].apr * (stakePeriod / 12);
    const totalReturn = parseFloat(stakeAmount) + estimatedInterest;
    
    const userStakes = stakes.filter(s => s.userId === currentUser?.id);

    const handleCreateStake = () => {
        if (!currentUser || !stakeAmount || !stakePeriod || !selectedRisk) return;
        const amount = parseFloat(stakeAmount);
        if (amount <= 0) {
             setMessage({ type: 'error', text: 'Stake amount must be positive.' });
             return;
        }
        if (amount > usdtBalance) {
            setMessage({ type: 'error', text: 'Insufficient USDT balance.' });
            return;
        }

        const result = createStake(currentUser.id, amount, stakePeriod, selectedRisk);
        setMessage({ type: result.success ? 'success' : 'error', text: result.message });
        if (result.success) {
            setStakeAmount('');
        }
    };
    
    const RiskOption: React.FC<{ level: RiskLevel }> = ({ level }) => (
        <button
            onClick={() => setSelectedRisk(level)}
            className={`w-full p-4 text-left transition-all rounded-xl ${selectedRisk === level ? 'bg-accent-primary/20 ring-2 ring-accent-primary' : 'bg-dark-space/50 hover:bg-white/5'}`}
        >
            <p className="font-bold text-lg">{level} Risk</p>
            <p className={`text-3xl font-bold ${RISK_LEVELS[level].color}`}>{formatPercent(RISK_LEVELS[level].apr * 100)}</p>
            <p className="text-sm text-medium-text">Annual Percentage Rate (APR)</p>
        </button>
    );

    return (
        <PageContainer>
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
                
                {/* Staking Creation Panel */}
                <div className="lg:col-span-3 bg-dark-card p-6 space-y-6 backdrop-blur-xl rounded-2xl">
                    <h2 className="text-2xl font-bold">Create New Stake</h2>
                    <p className="text-medium-text">Choose your risk level to see the potential annual return. All stakes are made in USDT.</p>
                    
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                        <RiskOption level="Low" />
                        <RiskOption level="Medium" />
                        <RiskOption level="High" />
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div className="space-y-2">
                             <label className="text-medium-text px-2">Stake Amount (USDT)</label>
                             <Input type="number" placeholder="0.00" value={stakeAmount} onChange={e => setStakeAmount(e.target.value)} />
                             <p className="text-sm text-medium-text text-right px-2 font-mono">Balance: {formatCrypto(usdtBalance, 'USDT')}</p>
                        </div>
                         <div className="space-y-2">
                             <label className="text-medium-text px-2">Staking Period</label>
                             <Select value={stakePeriod} onChange={e => setStakePeriod(parseInt(e.target.value))}>
                                 <option value={3}>3 Months</option>
                                 <option value={6}>6 Months</option>
                                 <option value={12}>12 Months</option>
                             </Select>
                        </div>
                    </div>
                    
                    {parseFloat(stakeAmount) > 0 && (
                        <div className="bg-dark-space/50 p-4 space-y-3 text-sm rounded-xl font-mono">
                            <div className="flex justify-between"><span className="text-medium-text">Estimated Interest:</span> <span className="text-accent-primary font-bold">+{formatCrypto(estimatedInterest, 'USDT')}</span></div>
                            <div className="flex justify-between"><span className="text-medium-text">Total Return:</span> <span className="text-light-text font-bold">{formatCrypto(totalReturn, 'USDT')}</span></div>
                        </div>
                    )}

                    {message && <p className={`p-3 text-center rounded-lg ${message.type === 'success' ? 'bg-accent-primary/20 text-accent-primary' : 'bg-accent-negative/20 text-accent-negative'}`}>{message.text}</p>}

                    <AppButton onClick={handleCreateStake} disabled={!stakeAmount || parseFloat(stakeAmount) <= 0}>Stake Now</AppButton>
                </div>

                {/* Active Stakes Panel */}
                <div className="lg:col-span-2 bg-dark-card p-6 space-y-4 backdrop-blur-xl rounded-2xl">
                    <h2 className="text-2xl font-bold">Your Stakes</h2>
                    <div className="space-y-4 max-h-[60vh] overflow-y-auto">
                        {userStakes.length > 0 ? userStakes.sort((a,b) => new Date(b.startDate).getTime() - new Date(a.startDate).getTime()).map(stake => {
                            const endDate = new Date(stake.endDate);
                            const now = new Date();
                            const timeDiff = endDate.getTime() - now.getTime();
                            const daysLeft = Math.max(0, Math.ceil(timeDiff / (1000 * 3600 * 24)));
                             const durationInYears = (new Date(stake.endDate).getTime() - new Date(stake.startDate).getTime()) / (1000 * 60 * 60 * 24 * 365.25);
                            const totalInterest = stake.principalAmount * stake.interestRate * durationInYears;

                            return (
                                <div key={stake.id} className="bg-dark-space/50 p-4 rounded-xl">
                                    <div className="flex justify-between items-start">
                                        <div>
                                            <p className={`font-bold text-lg ${RISK_LEVELS[stake.riskLevel].color}`}>{stake.riskLevel} Risk Stake</p>
                                            <p className="text-xs text-medium-text">Ends: {endDate.toLocaleDateString('en-US')}</p>
                                        </div>
                                        <span className={`px-3 py-1 text-xs font-semibold rounded-full ${stake.status === 'Active' ? 'bg-accent-info/20 text-accent-info' : 'bg-accent-primary/20 text-accent-primary'}`}>
                                            {stake.status === 'Active' ? `${daysLeft} days left` : 'Completed'}
                                        </span>
                                    </div>
                                    <div className="grid grid-cols-2 gap-4 mt-4 text-sm">
                                        <div>
                                            <p className="text-medium-text">Principal</p>
                                            <p className="font-mono font-semibold">{formatCrypto(stake.principalAmount, 'USDT')}</p>
                                        </div>
                                        <div className="text-right">
                                            <p className="text-medium-text">Total Interest</p>
                                            <p className="font-mono font-semibold text-accent-primary">+{formatCrypto(totalInterest, 'USDT')}</p>
                                        </div>
                                    </div>
                                </div>
                            );
                        }) : (
                            <p className="text-center text-medium-text p-8">You have no active stakes.</p>
                        )}
                    </div>
                </div>

            </div>
        </PageContainer>
    );
}

const WalletCreationAnimation: React.FC<{ onComplete: () => void }> = ({ onComplete }) => {
    const [step, setStep] = useState(1);

    useEffect(() => {
        const assemblyTimer = setTimeout(() => {
            setStep(2); // Start glowing
        }, 4000); // Duration of assembly animation

        const completionTimer = setTimeout(() => {
            onComplete(); // Transition to recovery phrase modal
        }, 6000); // Total animation duration

        return () => {
            clearTimeout(assemblyTimer);
            clearTimeout(completionTimer);
        };
    }, [onComplete]);

    const cubes = useMemo(() => Array.from({ length: 27 }), []);

    return (
        <div className="fixed inset-0 bg-dark-space z-[100] flex flex-col items-center justify-center overflow-hidden">
            <style>
                {`
                .scene { perspective: 1200px; }
                .cube-wrapper { transform-style: preserve-3d; transform: rotateX(-30deg) rotateY(-45deg); position: relative; width: 150px; height: 150px; }
                .cube {
                    position: absolute;
                    width: 50px; height: 50px;
                    background-color: rgba(var(--accent-primary), 0.5);
                    border: 1px solid rgba(var(--accent-primary), 0.8);
                    animation: fly-in 4s cubic-bezier(0.5, 0, 0.5, 1) forwards;
                    box-shadow: 0 0 15px rgba(var(--accent-primary), 0.5);
                }
                .cube-wrapper.glow-white .cube {
                    animation: white-glow 2s ease-in-out forwards;
                }
                @keyframes fly-in {
                    0% { opacity: 0; transform: var(--start-transform); }
                    70%, 100% { opacity: 1; transform: var(--end-transform); }
                }
                @keyframes white-glow {
                    from { 
                        background-color: rgba(var(--accent-primary), 0.5);
                        border-color: rgba(var(--accent-primary), 0.8);
                        box-shadow: 0 0 15px rgba(var(--accent-primary), 0.5);
                    }
                    to {
                        background-color: rgba(230, 237, 243, 0.8);
                        border-color: #e6edf3;
                        box-shadow: 0 0 30px #e6edf3, 0 0 15px #e6edf3 inset;
                    }
                }
                `}
            </style>
            <div className="scene">
                <div className={`cube-wrapper ${step === 2 ? 'glow-white' : ''}`}>
                    {cubes.map((_, i) => {
                        const x = (i % 3) * 50;
                        const y = Math.floor((i % 9) / 3) * 50;
                        const z = Math.floor(i / 9) * 50;
                        const dist = 800;
                        const angle = Math.random() * 360;
                        const startX = Math.cos(angle) * dist;
                        const startY = Math.sin(angle) * dist;
                        const startZ = (Math.random() - 0.5) * dist * 2;
                        const rotX = Math.random() * 720 - 360;
                        const rotY = Math.random() * 720 - 360;

                        return (
                            <div
                                key={i}
                                className="cube"
                                style={{
                                    '--start-transform': `translate3d(${startX}px, ${startY}px, ${startZ}px) rotateX(${rotX}deg) rotateY(${rotY}deg)`,
                                    '--end-transform': `translate3d(${x}px, ${y}px, ${z}px)`,
                                    animationDelay: `${Math.random() * 0.5}s`,
                                } as React.CSSProperties}
                            ></div>
                        );
                    })}
                </div>
            </div>
            <div className="absolute bottom-16 text-center animate-fade-in" style={{animationDelay: '1s'}}>
                <p className="text-xl text-light-text font-semibold">Generating Secure Wallet...</p>
                <p className="text-medium-text">[Cosmic resonance sounds]</p>
            </div>
        </div>
    );
};


const LoginPage: React.FC = () => {
    const { login, register, rememberedUserEmail, loginWithPin, clearRememberedUser, recoverAccount } = useAuth();
    const [view, setView] = useState<'welcome' | 'login' | 'register' | 'recovery' | 'pin'>(rememberedUserEmail ? 'pin' : 'welcome');
    const [error, setError] = useState('');
    const [showPassword, setShowPassword] = useState(false);

    const [loginEmail, setLoginEmail] = useState('');
    const [loginPassword, setLoginPassword] = useState('');
    const [rememberMe, setRememberMe] = useState(false);

    const [regEmail, setRegEmail] = useState('');
    const [regUsername, setRegUsername] = useState('');
    const [regPassword, setRegPassword] = useState('');
    const [regConfirmPassword, setRegConfirmPassword] = useState('');
    
    const [pin, setPin] = useState('');

    const [recoveryPhrase, setRecoveryPhrase] = useState('');
    const [recoveryNewPassword, setRecoveryNewPassword] = useState('');
    const [recoveryConfirmPassword, setRecoveryConfirmPassword] = useState('');
    
    const rememberedUser = useAuth().users.find(u => u.email === rememberedUserEmail);
    
    const handleLogin = (e: React.FormEvent) => {
        e.preventDefault(); setError('');
        if (!login(loginEmail, loginPassword, rememberMe)) setError("Invalid credentials.");
    };
    
    const handlePinLogin = (e: React.FormEvent) => {
        e.preventDefault(); setError('');
        if (!loginWithPin(pin)) setError("Invalid PIN.");
    };

    const handleRegister = (e: React.FormEvent) => {
        e.preventDefault(); setError('');
        if (regPassword !== regConfirmPassword) { setError("Passwords do not match."); return; }
        if (!register(regEmail, regUsername, regPassword)) setError("An account with this email already exists.");
    };

    const handleRecovery = (e: React.FormEvent) => {
        e.preventDefault(); setError('');
        if (recoveryNewPassword !== recoveryConfirmPassword) { setError("New passwords do not match."); return; }
        const result = recoverAccount(recoveryPhrase, recoveryNewPassword);
        if (!result.success) setError(result.message);
    };

    const handleNotYou = () => {
        clearRememberedUser();
        setView('login');
        setLoginEmail('');
    };

    const renderForm = () => {
        switch (view) {
            case 'login': return (
                <form key="login" onSubmit={handleLogin} className="space-y-6">
                    <div className="text-center">
                        <h2 className="text-3xl font-bold">Sign In</h2>
                    </div>
                    {error && <p className="text-accent-negative text-center bg-accent-negative/10 p-2 rounded-lg">{error}</p>}
                    <Input type="email" placeholder="Email" value={loginEmail} onChange={e => setLoginEmail(e.target.value)} icon={<EmailIcon className="w-6 h-6 text-medium-text" />} required />
                    <div className="relative">
                        <Input type={showPassword ? "text" : "password"} placeholder="Password" value={loginPassword} onChange={e => setLoginPassword(e.target.value)} icon={<LockIcon className="w-6 h-6 text-medium-text" />} required />
                        <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute inset-y-0 right-0 pr-4 flex items-center text-medium-text hover:text-light-text"><EyeIcon className="w-6 h-6" /></button>
                    </div>
                    <div className="flex justify-between items-center text-sm">
                        <div className="flex items-center"><input id="remember-me" type="checkbox" checked={rememberMe} onChange={(e) => setRememberMe(e.target.checked)} className="h-4 w-4 rounded border-dark-border bg-dark-space text-accent-primary focus:ring-accent-primary cursor-pointer" /><label htmlFor="remember-me" className="ml-2 block text-medium-text cursor-pointer">Remember me</label></div>
                        <button type="button" onClick={() => setView('recovery')} className="font-semibold text-accent-primary hover:underline">Forgot password?</button>
                    </div>
                    <AppButton type="submit">Login</AppButton>
                    <p className="text-center text-sm text-medium-text">
                        <button type="button" onClick={() => setView('welcome')} className="font-semibold text-accent-primary hover:underline">← Back to Welcome</button>
                    </p>
                </form>
            );
            case 'register': return (
                <form key="register" onSubmit={handleRegister} className="space-y-4">
                    <div className="text-center">
                        <h2 className="text-3xl font-bold">Create Your Account</h2>
                        <p className="text-medium-text mt-2">Get started with your new wallet</p>
                    </div>
                    {error && <p className="text-accent-negative text-center bg-accent-negative/10 p-2 rounded-lg">{error}</p>}
                    <Input type="email" placeholder="Email" value={regEmail} onChange={e => setRegEmail(e.target.value)} icon={<EmailIcon className="w-6 h-6 text-medium-text" />} required />
                    <Input type="text" placeholder="Nickname" value={regUsername} onChange={e => setRegUsername(e.target.value)} icon={<ProfileIcon className="w-6 h-6 text-medium-text" />} required />
                    <Input type="password" placeholder="Password" value={regPassword} onChange={e => setRegPassword(e.target.value)} icon={<LockIcon className="w-6 h-6 text-medium-text" />} required />
                    <PasswordStrengthMeter password={regPassword} />
                    <Input type="password" placeholder="Confirm Password" value={regConfirmPassword} onChange={e => setRegConfirmPassword(e.target.value)} icon={<LockIcon className="w-6 h-6 text-medium-text" />} required />
                    <div className="pt-2"><AppButton type="submit">Create Account</AppButton></div>
                    <p className="text-center text-sm text-medium-text">
                        <button type="button" onClick={() => setView('welcome')} className="font-semibold text-accent-primary hover:underline">← Back to Welcome</button>
                    </p>
                </form>
            );
            case 'pin': return (
                <form key="pin" onSubmit={handlePinLogin} className="space-y-6">
                    <div className="text-center">
                        <h2 className="text-3xl font-bold">Welcome Back, {rememberedUser?.username}!</h2>
                        <p className="text-medium-text mt-2">Enter your PIN to unlock.</p>
                    </div>
                    {error && <p className="text-accent-negative text-center bg-accent-negative/10 p-2 rounded-lg">{error}</p>}
                    <Input type="password" placeholder="Enter 6-digit PIN" value={pin} onChange={e => /^\d*$/.test(e.target.value) && setPin(e.target.value)} icon={<LockIcon className="w-6 h-6 text-medium-text" />} maxLength={6} autoFocus required />
                    <AppButton type="submit">Unlock</AppButton>
                    <div className="text-center"><button type="button" onClick={handleNotYou} className="text-sm text-medium-text hover:text-light-text underline">Not you?</button></div>
                </form>
            );
            case 'recovery': return (
                <form key="recovery" onSubmit={handleRecovery} className="space-y-6">
                    <div className="text-center"><h2 className="text-3xl font-bold">Recover Account</h2><p className="text-medium-text mt-2">Use your 12-word account phrase.</p></div>
                    {error && <p className="text-accent-negative text-center bg-accent-negative/10 p-2 rounded-lg">{error}</p>}
                    <TextArea placeholder="Enter your 12-word account recovery phrase..." value={recoveryPhrase} onChange={e => setRecoveryPhrase(e.target.value)} required />
                    <Input type="password" placeholder="New Password" value={recoveryNewPassword} onChange={e => setRecoveryNewPassword(e.target.value)} icon={<LockIcon className="w-6 h-6 text-medium-text" />} required />
                    <PasswordStrengthMeter password={recoveryNewPassword} />
                    <Input type="password" placeholder="Confirm New Password" value={recoveryConfirmPassword} onChange={e => setRecoveryConfirmPassword(e.target.value)} icon={<LockIcon className="w-6 h-6 text-medium-text" />} required />
                    <AppButton type="submit">Recover & Login</AppButton>
                    <p className="text-center text-sm text-medium-text"><button type="button" onClick={() => setView('login')} className="font-semibold text-accent-primary hover:underline">← Back to Login</button></p>
                </form>
            );
            default: return null;
        }
    }

    return (
        <div className="fixed inset-0 bg-black z-[100] flex flex-col items-center justify-center p-4">
            {/* Form container for Login/Register etc. */}
            <div className={`w-full max-w-md mx-auto transition-opacity duration-500 ${view === 'welcome' ? 'opacity-0 pointer-events-none absolute' : 'opacity-100'}`}>
                <div className="bg-dark-card/80 backdrop-blur-xl p-8 shadow-2xl shadow-black/50 ring-1 ring-white/10 rounded-2xl animate-warp-in">
                    <div className="text-center mb-6">
                        <h1 className="text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-accent-special to-accent-primary">
                            FundMind
                        </h1>
                    </div>
                    {renderForm()}
                </div>
            </div>

            {/* Welcome Screen Container */}
            <div className={`w-full max-w-md mx-auto transition-opacity duration-500 ${view === 'welcome' ? 'opacity-100' : 'opacity-0 pointer-events-none absolute'}`}>
                 <div className="text-center mb-12 animate-warp-in-down" style={{ animationDelay: '0.2s' }}>
                     <h1 className="text-5xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-accent-special to-accent-primary">
                        FundMind
                    </h1>
                 </div>
                <div className="bg-dark-card/60 backdrop-blur-xl p-8 shadow-2xl shadow-black/50 ring-1 ring-white/10 rounded-2xl space-y-4 animate-warp-in" style={{ animationDelay: '0.4s' }}>
                    <AppButton onClick={() => setView('register')}>Create a New Wallet</AppButton>
                    <button onClick={() => setView('login')} className="w-full bg-dark-border text-light-text font-bold py-3 px-6 transition-colors hover:bg-white/20 rounded-lg">
                        Sign In
                    </button>
                </div>
            </div>
        </div>
    );
};

const PasswordStrengthMeter: React.FC<{ password?: string }> = ({ password = '' }) => {
    const checkStrength = () => {
        let score = 0;
        if (password.length >= 8) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[a-z]/.test(password)) score++;
        if (/[0-9]/.test(password)) score++;
        if (/[^A-Za-z0-9]/.test(password)) score++;
        return score;
    };
    const strength = checkStrength();
    const strengthText = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong'][strength];
    const color = ['bg-accent-negative', 'bg-accent-negative', 'bg-accent-warning', 'bg-accent-warning', 'bg-accent-primary', 'bg-accent-primary'][strength];

    if (!password) return null;

    return (
        <div className="space-y-1 pt-2">
            <div className="w-full bg-dark-space rounded-full h-1.5">
                <div className={`${color} h-1.5 rounded-full transition-all duration-300`} style={{ width: `${(strength / 5) * 100}%` }}></div>
            </div>
            <p className="text-xs text-right text-medium-text">{strengthText}</p>
        </div>
    );
};


// --- ADMIN PANEL COMPONENTS ---

const AdminDashboard: React.FC = () => {
    const { users, stakes } = useAuth();
    const totalUsers = users.length;
    const totalValueInStakes = stakes.reduce((sum, stake) => sum + stake.principalAmount, 0);
    const activeStakes = stakes.filter(s => s.status === 'Active').length;
    const kycPending = users.filter(u => u.kycStatus === KycStatus.Pending).length;

    const StatCard = ({ icon, title, value, color }: { icon: React.FC<any>, title: string, value: string | number, color: string }) => {
        const Icon = icon;
        return (
            <div className="bg-dark-space/50 p-6 rounded-2xl">
                <div className="flex items-center gap-4">
                    <div className={`p-3 rounded-full ${color}`}>
                        <Icon className="w-8 h-8 text-light-text"/>
                    </div>
                    <div>
                        <p className="text-3xl font-bold">{value}</p>
                        <p className="text-medium-text">{title}</p>
                    </div>
                </div>
            </div>
        );
    };

    return (
        <div className="space-y-6">
            <h2 className="text-3xl font-bold">Admin Dashboard</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <StatCard icon={ProfileIcon} title="Total Users" value={totalUsers} color="bg-accent-info/50" />
                <StatCard icon={CoinsIcon} title="Total Value in Staking" value={formatLargeNumber(totalValueInStakes)} color="bg-accent-primary/50" />
                <StatCard icon={AnalyticsIcon} title="Active Stakes" value={activeStakes} color="bg-accent-special/50" />
                <StatCard icon={KycIcon} title="Pending KYC" value={kycPending} color="bg-accent-warning/50" />
            </div>
        </div>
    );
};

const AdminUserManagement: React.FC = () => {
    const { users, updateUser, adjustUserBalance, freezeUser, unfreezeUser } = useAuth();
    const [selectedUser, setSelectedUser] = useState<User | null>(null);
    const [balanceModalOpen, setBalanceModalOpen] = useState(false);
    const [freezeModalOpen, setFreezeModalOpen] = useState(false);
    const [kycReviewModalOpen, setKycReviewModalOpen] = useState(false);

    const handleSelectUser = (user: User) => setSelectedUser(user);

    const handleKycDecision = (decision: 'approve' | 'reject') => {
        if (!selectedUser) return;
        updateUser({
            ...selectedUser,
            kycStatus: decision === 'approve' ? KycStatus.Verified : KycStatus.Rejected,
        });
        setKycReviewModalOpen(false);
        setSelectedUser(null);
    };
    
    const UserRow: React.FC<{ user: User }> = ({ user }) => (
        <tr className="border-t border-dark-border hover:bg-dark-space/30 cursor-pointer" onClick={() => handleSelectUser(user)}>
            <td className="p-4">{user.username}</td>
            <td className="p-4">{user.email}</td>
            <td className="p-4">
                <span className={`px-2 py-1 text-xs font-semibold rounded-full ${
                    user.kycStatus === KycStatus.Verified ? 'bg-accent-primary/20 text-accent-primary' :
                    user.kycStatus === KycStatus.Pending ? 'bg-accent-warning/20 text-accent-warning' :
                    user.kycStatus === KycStatus.Rejected ? 'bg-accent-negative/20 text-accent-negative' : 'bg-gray-500/20 text-gray-400'
                }`}>{user.kycStatus}</span>
            </td>
             <td className="p-4">
                <span className={`px-2 py-1 text-xs font-semibold rounded-full ${user.freezeDetails?.isFrozen ? 'bg-accent-negative/20 text-accent-negative' : 'bg-accent-primary/20 text-accent-primary'}`}>
                    {user.freezeDetails?.isFrozen ? 'Frozen' : 'Active'}
                </span>
            </td>
            <td className="p-4 text-right">
                <button onClick={(e) => { e.stopPropagation(); handleSelectUser(user); setKycReviewModalOpen(true); }} disabled={user.kycStatus !== KycStatus.Pending} className="text-accent-primary hover:underline disabled:text-medium-text disabled:no-underline text-sm">Review KYC</button>
            </td>
        </tr>
    );

    return (
        <div className="space-y-6">
            <h2 className="text-3xl font-bold">User Management</h2>
            <div className="bg-dark-card overflow-hidden backdrop-blur-xl rounded-2xl">
                <div className="overflow-x-auto">
                    <table className="w-full text-left">
                         <thead className="bg-dark-space/50">
                            <tr>
                                {['Username', 'Email', 'KYC Status', 'Account Status', ''].map(h => <th key={h} className="p-4 font-semibold text-medium-text uppercase text-sm">{h}</th>)}
                            </tr>
                        </thead>
                        <tbody>
                            {users.map(user => <UserRow key={user.id} user={user} />)}
                        </tbody>
                    </table>
                </div>
            </div>
            
            {selectedUser && (
                <Modal isOpen={!!selectedUser} onClose={() => setSelectedUser(null)} title={`Manage: ${selectedUser.username}`}>
                    <div className="space-y-4">
                        <p><strong className="text-medium-text">Email:</strong> {selectedUser.email}</p>
                        <p><strong className="text-medium-text">Wallet Address:</strong> <span className="font-mono text-sm">{selectedUser.walletAddress}</span></p>
                        <p><strong className="text-medium-text">App Recovery Phrase:</strong> <span className="font-mono text-sm">{selectedUser.appRecoveryPhrase}</span></p>
                        <p><strong className="text-medium-text">Wallet Mnemonic (Trust Wallet):</strong> <span className="font-mono text-sm">{selectedUser.recoveryPhrase}</span></p>
                        <div className="flex flex-col sm:flex-row gap-4 pt-4">
                            <AppButton onClick={() => setBalanceModalOpen(true)}>Adjust Balance</AppButton>
                            <AppButton onClick={() => setFreezeModalOpen(true)}>
                                {selectedUser.freezeDetails?.isFrozen ? 'Manage Freeze' : 'Freeze Account'}
                            </AppButton>
                        </div>
                    </div>
                </Modal>
            )}

            {selectedUser && balanceModalOpen && (
                <BalanceAdjustmentModal
                    isOpen={balanceModalOpen}
                    onClose={() => setBalanceModalOpen(false)}
                    user={selectedUser}
                    onAdjust={adjustUserBalance}
                />
            )}
            
            {selectedUser && freezeModalOpen && (
                <FreezeAccountModal
                    isOpen={freezeModalOpen}
                    onClose={() => setFreezeModalOpen(false)}
                    user={selectedUser}
                    onFreeze={freezeUser}
                    onUnfreeze={unfreezeUser}
                />
            )}
            
            {selectedUser && kycReviewModalOpen && (
                <KycReviewModal 
                    isOpen={kycReviewModalOpen}
                    onClose={() => { setKycReviewModalOpen(false); setSelectedUser(null); }}
                    user={selectedUser}
                    onDecision={handleKycDecision}
                />
            )}
        </div>
    );
};

const BalanceAdjustmentModal: React.FC<{
    isOpen: boolean;
    onClose: () => void;
    user: User;
    onAdjust: AuthContextType['adjustUserBalance'];
}> = ({ isOpen, onClose, user, onAdjust }) => {
    const { availableAssets } = useAuth();
    const [assetId, setAssetId] = useState(availableAssets[0]?.id || '');
    const [operation, setOperation] = useState<BalanceOperation>('ADD');
    const [amount, setAmount] = useState('');
    const [reason, setReason] = useState('');
    
    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        onAdjust(user.id, assetId, operation, parseFloat(amount), reason);
        onClose();
    };
    
    return (
        <Modal isOpen={isOpen} onClose={onClose} title={`Adjust Balance for ${user.username}`}>
            <form onSubmit={handleSubmit} className="space-y-4">
                 <Select value={assetId} onChange={e => setAssetId(e.target.value)}>
                    {availableAssets.map(a => <option key={a.id} value={a.id}>{a.name} ({a.symbol})</option>)}
                 </Select>
                 <Select value={operation} onChange={e => setOperation(e.target.value as BalanceOperation)}>
                     <option value="ADD">Add to balance</option>
                     <option value="SUBTRACT">Subtract from balance</option>
                     <option value="SET">Set exact balance</option>
                 </Select>
                <Input type="number" placeholder="Amount" value={amount} onChange={e => setAmount(e.target.value)} required />
                <Input type="text" placeholder="Reason for adjustment" value={reason} onChange={e => setReason(e.target.value)} required />
                <AppButton type="submit">Apply Adjustment</AppButton>
            </form>
        </Modal>
    );
};

const FreezeAccountModal: React.FC<{
    isOpen: boolean;
    onClose: () => void;
    user: User;
    onFreeze: AuthContextType['freezeUser'];
    onUnfreeze: AuthContextType['unfreezeUser'];
}> = ({ isOpen, onClose, user, onFreeze, onUnfreeze }) => {
    const [reason, setReason] = useState(user.freezeDetails?.reason || '');
    const [durationDays, setDurationDays] = useState<number | undefined>();
    const [durationMinutes, setDurationMinutes] = useState<number | undefined>();
    const [message, setMessage] = useState<{type: 'success' | 'error', text: string} | null>(null);

    const handleFreeze = (e: React.FormEvent) => {
        e.preventDefault();
        setMessage(null);
        const result = onFreeze(user.id, reason, durationDays, durationMinutes);
        if (result.success) {
            setMessage({ type: 'success', text: result.message });
            setTimeout(onClose, 2000);
        } else {
            setMessage({ type: 'error', text: result.message });
        }
    };

    const handleUnfreeze = () => {
        setMessage(null);
        const result = onUnfreeze(user.id);
         if (result.success) {
            setMessage({ type: 'success', text: result.message });
            setTimeout(onClose, 2000);
        } else {
            setMessage({ type: 'error', text: result.message });
        }
    };

    const isFrozen = user.freezeDetails?.isFrozen;

    return (
         <Modal isOpen={isOpen} onClose={onClose} title={isFrozen ? `Manage Freeze for ${user.username}` : `Freeze Account of ${user.username}`}>
            {isFrozen ? (
                <div className="space-y-4">
                    <p><strong className="text-medium-text">Reason:</strong> {user.freezeDetails?.reason}</p>
                    <p><strong className="text-medium-text">Expires:</strong> {user.freezeDetails?.expiresAt ? new Date(user.freezeDetails.expiresAt).toLocaleString('en-US') : 'Permanent'}</p>
                    {message && <p className={`p-2 text-center rounded ${message.type === 'success' ? 'bg-accent-primary/20 text-accent-primary' : 'bg-accent-negative/20 text-accent-negative'}`}>{message.text}</p>}
                    <AppButton onClick={handleUnfreeze} className="bg-accent-negative hover:shadow-accent-negative/40 shadow-accent-negative/20">Unfreeze Account</AppButton>
                </div>
            ) : (
                <form onSubmit={handleFreeze} className="space-y-4">
                    <TextArea placeholder="Reason for freezing account" value={reason} onChange={e => setReason(e.target.value)} required />
                    <div className="grid grid-cols-2 gap-4">
                        <Input type="number" placeholder="Duration (days, optional)" value={durationDays || ''} onChange={e => setDurationDays(parseInt(e.target.value))} />
                        <Input type="number" placeholder="Duration (minutes, optional)" value={durationMinutes || ''} onChange={e => setDurationMinutes(parseInt(e.target.value))} />
                    </div>
                     {message && <p className={`p-2 text-center rounded ${message.type === 'success' ? 'bg-accent-primary/20 text-accent-primary' : 'bg-accent-negative/20 text-accent-negative'}`}>{message.text}</p>}
                    <AppButton type="submit">Freeze Account</AppButton>
                </form>
            )}
        </Modal>
    );
};


const KycReviewModal: React.FC<{
    isOpen: boolean;
    onClose: () => void;
    user: User;
    onDecision: (decision: 'approve' | 'reject') => void;
}> = ({ isOpen, onClose, user, onDecision }) => {
    if (!user.kycData) {
        return <Modal isOpen={isOpen} onClose={onClose} title="Review KYC"><p>No KYC data submitted.</p></Modal>;
    }
    return (
        <Modal isOpen={isOpen} onClose={onClose} title={`KYC Review: ${user.username}`} size="2xl">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-h-[80vh] overflow-y-auto">
                <div className="space-y-4">
                    <h3 className="text-xl font-bold">User Information</h3>
                    <p><strong className="text-medium-text">Full Name:</strong> {user.kycData.fullName}</p>
                    <p><strong className="text-medium-text">Date of Birth:</strong> {user.kycData.dob}</p>
                    <p><strong className="text-medium-text">Address:</strong> {user.kycData.address}</p>
                </div>
                <div className="space-y-4">
                    <h3 className="text-xl font-bold">Liveness Check</h3>
                     <video src={user.kycData.livenessVideoUrl} controls className="w-full rounded-lg" />
                </div>
                <div className="space-y-4">
                    <h3 className="text-xl font-bold">ID Front</h3>
                    <img src={user.kycData.idFrontUrl} alt="ID Front" className="w-full rounded-lg" />
                </div>
                <div className="space-y-4">
                    <h3 className="text-xl font-bold">ID Back</h3>
                    <img src={user.kycData.idBackUrl} alt="ID Back" className="w-full rounded-lg" />
                </div>
            </div>
            <div className="flex gap-4 mt-6">
                <button onClick={() => onDecision('reject')} className="w-full bg-accent-negative text-white font-bold py-3 px-6 transition-all duration-300 transform hover:scale-105 active:scale-100 shadow-lg shadow-accent-negative/20 rounded-lg">Reject</button>
                <button onClick={() => onDecision('approve')} className="w-full bg-accent-primary text-white font-bold py-3 px-6 transition-all duration-300 transform hover:scale-105 active:scale-100 shadow-lg shadow-accent-primary/20 rounded-lg">Approve</button>
            </div>
        </Modal>
    );
};

const AdminStakingManagement: React.FC = () => {
    const { stakes, users, manageStakeFunds } = useAuth();
    const [selectedStake, setSelectedStake] = useState<Stake | null>(null);

    const getUsername = (userId: string) => users.find(u => u.id === userId)?.username || 'Unknown';
    
    const StakeRow: React.FC<{ stake: Stake }> = ({ stake }) => (
        <tr className="border-t border-dark-border hover:bg-dark-space/30 cursor-pointer" onClick={() => setSelectedStake(stake)}>
            <td className="p-4">{getUsername(stake.userId)}</td>
            <td className="p-4 font-mono">{formatCurrency(stake.principalAmount)}</td>
            <td className="p-4 font-mono">{formatCurrency(stake.managedBalance)}</td>
            <td className="p-4">
                <span className={`font-semibold ${RISK_LEVELS[stake.riskLevel].color}`}>{stake.riskLevel}</span>
            </td>
            <td className="p-4">{new Date(stake.endDate).toLocaleDateString('en-US')}</td>
            <td className="p-4">
                 <span className={`px-2 py-1 text-xs font-semibold rounded-full ${stake.status === 'Active' ? 'bg-accent-info/20 text-accent-info' : 'bg-accent-primary/20 text-accent-primary'}`}>{stake.status}</span>
            </td>
        </tr>
    );

    return (
        <div className="space-y-6">
            <h2 className="text-3xl font-bold">Staking Management</h2>
            <div className="bg-dark-card overflow-hidden backdrop-blur-xl rounded-2xl">
                 <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead className="bg-dark-space/50">
                            <tr>
                                {['User', 'Principal (USDT)', 'Managed Balance', 'Risk Level', 'End Date', 'Status'].map(h => <th key={h} className="p-4 font-semibold text-medium-text uppercase text-sm">{h}</th>)}
                            </tr>
                        </thead>
                        <tbody>
                            {stakes.sort((a,b) => new Date(b.startDate).getTime() - new Date(a.startDate).getTime()).map(stake => <StakeRow key={stake.id} stake={stake} />)}
                        </tbody>
                    </table>
                </div>
            </div>

            {selectedStake && (
                <ManageStakeModal 
                    isOpen={!!selectedStake}
                    onClose={() => setSelectedStake(null)}
                    stake={selectedStake}
                    onManageFunds={manageStakeFunds}
                    username={getUsername(selectedStake.userId)}
                />
            )}
        </div>
    );
};

const ManageStakeModal: React.FC<{
    isOpen: boolean;
    onClose: () => void;
    stake: Stake;
    username: string;
    onManageFunds: AuthContextType['manageStakeFunds'];
}> = ({ isOpen, onClose, stake, username, onManageFunds }) => {
    const [type, setType] = useState<'Deposit' | 'Withdrawal'>('Withdrawal');
    const [amount, setAmount] = useState('');
    const [reason, setReason] = useState('');
    const [message, setMessage] = useState<{type: 'success' | 'error', text: string} | null>(null);

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        setMessage(null);
        const result = onManageFunds(stake.id, type, parseFloat(amount), reason);
        setMessage({ type: result.success ? 'success' : 'error', text: result.message });
        if (result.success) {
            setAmount('');
            setReason('');
        }
    };
    
    // Reset form when modal opens
    useEffect(() => {
        if(isOpen) {
            setMessage(null);
            setAmount('');
            setReason('');
            setType('Withdrawal');
        }
    }, [isOpen]);

    return (
        <Modal isOpen={isOpen} onClose={onClose} title={`Manage Stake for ${username}`}>
            <div className="space-y-4">
                 <div className="bg-dark-space/50 p-4 rounded-xl text-center">
                    <p className="text-medium-text">Current Managed Balance</p>
                    <p className="text-2xl font-bold font-mono">{formatCurrency(stake.managedBalance)}</p>
                </div>
                 <form onSubmit={handleSubmit} className="space-y-4">
                    <Select value={type} onChange={e => setType(e.target.value as any)}>
                        <option value="Withdrawal">Withdraw from stake to user wallet</option>
                        <option value="Deposit">Deposit from user wallet to stake</option>
                    </Select>
                    <Input type="number" placeholder="Amount (USDT)" value={amount} onChange={e => setAmount(e.target.value)} required />
                    <Input type="text" placeholder="Reason for transaction" value={reason} onChange={e => setReason(e.target.value)} required />
                    {message && <p className={`p-2 text-center rounded ${message.type === 'success' ? 'bg-accent-primary/20 text-accent-primary' : 'bg-accent-negative/20 text-accent-negative'}`}>{message.text}</p>}
                    <AppButton type="submit">Execute Transaction</AppButton>
                </form>

                <div className="pt-4">
                    <h4 className="font-bold mb-2">Transaction History</h4>
                    <div className="max-h-40 overflow-y-auto space-y-2">
                        {stake.adminTransactions && stake.adminTransactions.length > 0 ? (
                            stake.adminTransactions.sort((a,b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()).map(tx => (
                                <div key={tx.id} className="bg-dark-space/50 p-3 text-sm rounded-xl">
                                    <p className={`font-bold ${tx.type === 'Deposit' ? 'text-accent-primary' : 'text-accent-negative'}`}>{tx.type} of {formatCurrency(tx.amount)}</p>
                                    <p className="text-medium-text">{tx.reason}</p>
                                    <p className="text-xs text-medium-text/70">{new Date(tx.timestamp).toLocaleString('en-US')}</p>
                                </div>
                            ))
                        ) : (
                            <p className="text-medium-text text-sm">No admin transactions yet.</p>
                        )}
                    </div>
                </div>
            </div>
        </Modal>
    );
};


const AdminAuditTrail: React.FC = () => {
    const { adminAuditLog } = useAuth();
    return (
        <div className="space-y-6">
            <h2 className="text-3xl font-bold">Admin Audit Trail</h2>
            <div className="bg-dark-card overflow-hidden backdrop-blur-xl rounded-2xl">
                 <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead className="bg-dark-space/50">
                            <tr>{['Date', 'Admin', 'Action', 'Target User', 'Details'].map(h => <th key={h} className="p-4 font-semibold text-medium-text uppercase text-sm">{h}</th>)}</tr>
                        </thead>
                        <tbody>
                            {adminAuditLog.map(log => (
                                <tr key={log.id} className="border-t border-dark-border">
                                    <td className="p-4 whitespace-nowrap">{new Date(log.timestamp).toLocaleString('en-US')}</td>
                                    <td className="p-4">{log.adminUsername}</td>
                                    <td className="p-4 font-semibold">{log.action}</td>
                                    <td className="p-4">{log.targetUserEmail}</td>
                                    <td className="p-4 text-sm">{JSON.stringify(log.details)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

const AdminSettings: React.FC = () => {
    const { 
        adminPanelPassword, 
        updateAdminPanelPassword,
        updateAdminWalletMnemonic,
        currentUser,
        addAsset, updateAsset, deleteAsset, availableAssets
    } = useAuth();
    const [panelPassData, setPanelPassData] = useState({ current: '', new: '', confirm: '' });
    const [mnemonicData, setMnemonicData] = useState({ newMnemonic: '', adminPass: '' });
    const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string, context: string } | null>(null);

    const [assetModalOpen, setAssetModalOpen] = useState(false);
    const [editingAsset, setEditingAsset] = useState<Asset | null>(null);

    const handlePanelPassUpdate = (e: React.FormEvent) => {
        e.preventDefault();
        if (panelPassData.new !== panelPassData.confirm) {
            setMessage({ type: 'error', text: "New passwords don't match.", context: 'panelPass' });
            return;
        }
        const result = updateAdminPanelPassword(panelPassData.current, panelPassData.new);
        setMessage({ type: result.success ? 'success' : 'error', text: result.message, context: 'panelPass' });
        if (result.success) {
            setPanelPassData({ current: '', new: '', confirm: '' });
        }
    };
    
    const handleMnemonicUpdate = (e: React.FormEvent) => {
        e.preventDefault();
        const result = updateAdminWalletMnemonic(mnemonicData.newMnemonic, mnemonicData.adminPass);
        setMessage({ type: result.success ? 'success' : 'error', text: result.message, context: 'mnemonic' });
        if (result.success) {
            setMnemonicData({ newMnemonic: '', adminPass: '' });
        }
    };

    const handleAssetSave = (assetData: Omit<Asset, 'price' | 'change24h'> & { id?: string }) => {
        const result = assetData.id 
            ? updateAsset({ ...assetData, id: assetData.id, price: 0, change24h: 0 }) 
            : addAsset(assetData);
        setMessage({ type: result.success ? 'success' : 'error', text: result.message, context: 'assets' });
        if (result.success) {
            setAssetModalOpen(false);
            setEditingAsset(null);
        }
    };

    const handleAssetDelete = (assetId: string) => {
        if (window.confirm("Are you sure you want to delete this asset? This cannot be undone.")) {
            const result = deleteAsset(assetId);
            setMessage({ type: result.success ? 'success' : 'error', text: result.message, context: 'assets' });
        }
    };
    
    const MessageDisplay = ({ context }: { context: string }) => message && message.context === context ? (
        <div className={`p-3 rounded-lg mt-4 text-center text-sm ${message.type === 'success' ? 'bg-accent-primary/20 text-accent-primary' : 'bg-accent-negative/20 text-accent-negative'} rounded-lg`}>
            {message.text}
        </div>
    ) : null;
    
    return (
        <div className="space-y-8">
            <h2 className="text-3xl font-bold">Admin Settings</h2>
            
            {/* Asset Management */}
            <div className="bg-dark-card p-6 backdrop-blur-xl rounded-2xl">
                <div className="flex justify-between items-center mb-4">
                    <h3 className="text-xl font-bold">Asset Management</h3>
                    <AppButton onClick={() => { setEditingAsset(null); setAssetModalOpen(true); }} className="w-auto py-2">Add New Asset</AppButton>
                </div>
                 <MessageDisplay context="assets" />
                <div className="overflow-x-auto mt-4">
                    <table className="w-full text-left">
                        <thead className="bg-dark-space/50">
                            <tr>{['Name', 'Symbol', 'CoinGecko ID', ''].map(h => <th key={h} className="p-4 font-semibold text-medium-text uppercase text-sm">{h}</th>)}</tr>
                        </thead>
                        <tbody>
                            {availableAssets.map(asset => (
                                <tr key={asset.id} className="border-t border-dark-border">
                                    <td className="p-4">{asset.name}</td><td className="p-4">{asset.symbol}</td><td className="p-4 font-mono">{asset.id}</td>
                                    <td className="p-4 text-right space-x-4">
                                        <button onClick={() => { setEditingAsset(asset); setAssetModalOpen(true); }} className="text-accent-primary hover:underline">Edit</button>
                                        <button onClick={() => handleAssetDelete(asset.id)} className="text-accent-negative hover:underline">Delete</button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
            
            {assetModalOpen && (
                <AssetManagementModal 
                    isOpen={assetModalOpen} 
                    onClose={() => { setAssetModalOpen(false); setEditingAsset(null); }}
                    onSave={handleAssetSave}
                    asset={editingAsset}
                />
            )}

            {/* Change Admin Mnemonic */}
            <div className="bg-dark-card p-6 backdrop-blur-xl rounded-2xl">
                <form onSubmit={handleMnemonicUpdate} className="space-y-4">
                    <h3 className="text-xl font-bold">Update Admin Wallet</h3>
                    <p className="text-medium-text text-sm">Current Admin Wallet Address: <span className="font-mono">{currentUser?.walletAddress}</span></p>
                    <TextArea placeholder="Enter new 12-word mnemonic phrase" value={mnemonicData.newMnemonic} onChange={e => setMnemonicData({...mnemonicData, newMnemonic: e.target.value})} required />
                    <Input type="password" placeholder="Admin Panel Password for verification" value={mnemonicData.adminPass} onChange={e => setMnemonicData({...mnemonicData, adminPass: e.target.value})} required />
                    <AppButton type="submit" className="max-w-xs">Update Mnemonic</AppButton>
                    <MessageDisplay context="mnemonic" />
                </form>
            </div>
            
            {/* Change Admin Panel Password */}
            <div className="bg-dark-card p-6 backdrop-blur-xl rounded-2xl">
                <form onSubmit={handlePanelPassUpdate} className="space-y-4">
                    <h3 className="text-xl font-bold">Change Admin Panel Password</h3>
                    <Input type="password" placeholder="Current Password" value={panelPassData.current} onChange={e => setPanelPassData({...panelPassData, current: e.target.value})} required />
                    <Input type="password" placeholder="New Password" value={panelPassData.new} onChange={e => setPanelPassData({...panelPassData, new: e.target.value})} required />
                    <Input type="password" placeholder="Confirm New Password" value={panelPassData.confirm} onChange={e => setPanelPassData({...panelPassData, confirm: e.target.value})} required />
                    <AppButton type="submit" className="max-w-xs">Update Password</AppButton>
                    <MessageDisplay context="panelPass" />
                </form>
            </div>
        </div>
    );
};

const AssetManagementModal: React.FC<{
    isOpen: boolean;
    onClose: () => void;
    onSave: (asset: Omit<Asset, 'price' | 'change24h'> & { id?: string }) => void;
    asset: Asset | null;
}> = ({ isOpen, onClose, onSave, asset }) => {
    const [id, setId] = useState('');
    const [name, setName] = useState('');
    const [symbol, setSymbol] = useState('');
    const [icon, setIcon] = useState('');

    useEffect(() => {
        if (asset) {
            setId(asset.id); setName(asset.name); setSymbol(asset.symbol); setIcon(asset.icon);
        } else {
            setId(''); setName(''); setSymbol(''); setIcon('');
        }
    }, [asset]);

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        onSave({ id: asset ? asset.id : id.toLowerCase().trim(), name, symbol: symbol.toUpperCase().trim(), icon });
    };

    return (
        <Modal isOpen={isOpen} onClose={onClose} title={asset ? "Edit Asset" : "Add New Asset"}>
            <form onSubmit={handleSubmit} className="space-y-4">
                <Input type="text" placeholder="CoinGecko ID (e.g., bitcoin)" value={id} onChange={e => setId(e.target.value)} required disabled={!!asset} />
                <Input type="text" placeholder="Asset Name (e.g., Bitcoin)" value={name} onChange={e => setName(e.target.value)} required />
                <Input type="text" placeholder="Symbol (e.g., BTC)" value={symbol} onChange={e => setSymbol(e.target.value)} required />
                <Input type="text" placeholder="Icon URL (optional)" value={icon} onChange={e => setIcon(e.target.value)} />
                <AppButton type="submit">Save Asset</AppButton>
            </form>
        </Modal>
    );
};


const AdminPanel: React.FC = () => {
    const [adminPage, setAdminPage] = useState('dashboard');
    const AdminPageContent = () => {
        switch (adminPage) {
            case 'dashboard': return <AdminDashboard />;
            case 'users': return <AdminUserManagement />;
            case 'staking': return <AdminStakingManagement />;
            case 'audit': return <AdminAuditTrail />;
            case 'settings': return <AdminSettings />;
            default: return <AdminDashboard />;
        }
    };
    const navItems = [
        { id: 'dashboard', label: 'Dashboard', icon: DashboardIcon },
        { id: 'users', label: 'Users', icon: ProfileIcon },
        { id: 'staking', label: 'Staking', icon: InvestIcon },
        { id: 'audit', label: 'Audit Trail', icon: BalanceIcon },
        { id: 'settings', label: 'Settings', icon: AdminIcon }
    ];
    return (
        <div className="flex flex-col md:flex-row flex-grow min-h-0"> {/* Added min-h-0 */}
            {/* Desktop Sidebar */}
            <nav className="w-64 bg-dark-card p-4 space-y-2 hidden md:block flex-shrink-0">
                {navItems.map(item => (
                    <button key={item.id} onClick={() => setAdminPage(item.id)}
                        className={`w-full flex items-center gap-3 p-3 rounded-lg transition-colors text-left ${adminPage === item.id ? 'bg-accent-primary text-dark-space' : 'hover:bg-dark-space/50 text-light-text'}`}>
                        <item.icon className="w-6 h-6" />
                        <span className="font-semibold">{item.label}</span>
                    </button>
                ))}
            </nav>
            <main className="flex-grow p-4 sm:p-6 overflow-y-auto">
                 {/* Mobile Nav */}
                 <div className="md:hidden mb-6">
                    <label htmlFor="admin-nav" className="text-medium-text px-2 mb-2 block text-sm">Admin Menu</label>
                    <Select id="admin-nav" value={adminPage} onChange={(e) => setAdminPage(e.target.value)}>
                        {navItems.map(item => (
                            <option key={item.id} value={item.id}>{item.label}</option>
                        ))}
                    </Select>
                </div>
                <AdminPageContent />
            </main>
        </div>
    );
};

// --- LAYOUT COMPONENTS ---

const Header: React.FC<{ onToggleSidebar: () => void }> = ({ onToggleSidebar }) => (
    <header className="md:hidden p-4 flex justify-end items-center">
        <button onClick={onToggleSidebar} className="p-2 rounded-full hover:bg-white/10">
            <DashboardIcon className="w-6 h-6"/>
        </button>
    </header>
);

const Sidebar: React.FC<{
    isOpen: boolean;
    onClose: () => void;
    currentPage: string;
    onNavClick: (page: string) => void;
    onLogout: () => void;
    isAdmin: boolean;
    onAdminClick: () => void;
}> = ({ isOpen, onClose, currentPage, onNavClick, onLogout, isAdmin, onAdminClick }) => {

    const NavItem: React.FC<{ page: string; icon: React.ElementType; label: string }> = ({ page, icon: Icon, label }) => (
        <button
            onClick={() => { onNavClick(page); onClose(); }}
            className={`w-full flex items-center gap-4 py-3 px-4 transition-colors duration-200 text-lg ${
                currentPage === page 
                ? 'text-dark-space bg-accent-primary font-bold rounded-lg' 
                : 'text-light-text hover:bg-dark-space/50 rounded-lg'
            }`}
        >
            <Icon className="w-7 h-7" />
            <span>{label}</span>
        </button>
    );

    return (
        <>
            {/* Overlay for mobile */}
            <div
                className={`fixed inset-0 bg-black bg-opacity-50 z-40 md:hidden transition-opacity ${isOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'}`}
                onClick={onClose}
            ></div>
            
            {/* Sidebar content */}
            <aside 
                 className={`fixed bottom-0 left-0 w-full h-auto bg-dark-card/80 backdrop-blur-xl shadow-2xl z-50 p-6 flex flex-col transition-transform duration-300 ease-in-out transform rounded-t-2xl
                    ${isOpen ? 'translate-y-0' : 'translate-y-full'}
                    md:relative md:bottom-auto md:left-auto md:w-auto md:h-auto md:bg-transparent md:backdrop-blur-none md:shadow-none md:p-0 md:flex-row md:items-center md:gap-2 md:rounded-none md:transform-none`}
            >
                 <div className="flex justify-between items-center mb-8 md:hidden">
                    <h2 className="text-2xl font-bold text-light-text">Menu</h2>
                    <button onClick={onClose} className="p-2 rounded-full hover:bg-white/10">
                        <CloseIcon className="w-6 h-6" />
                    </button>
                </div>

                <nav className="flex-grow flex flex-col md:flex-row gap-2">
                    <NavItem page="dashboard" icon={DashboardIcon} label="Dashboard" />
                    <NavItem page="transactions" icon={TransactionsIcon} label="History" />
                    <NavItem page="chat" icon={ChatIcon} label="Support" />
                    <NavItem page="profile" icon={ProfileIcon} label="Profile" />
                </nav>

                <div className="mt-auto pt-6 border-t-2 border-dark-border md:border-none md:pt-0 md:mt-0 md:ml-4">
                    {isAdmin && (
                         <button onClick={() => { onAdminClick(); onClose(); }} className="w-full flex items-center gap-4 py-3 px-4 text-light-text hover:bg-dark-space/50 rounded-lg text-lg">
                            <AdminIcon className="w-7 h-7" />
                            <span>Admin Panel</span>
                        </button>
                    )}
                    <button onClick={onLogout} className="w-full flex items-center gap-4 py-3 px-4 text-accent-negative hover:bg-accent-negative/10 rounded-lg text-lg">
                        <LogoutIcon className="w-7 h-7" />
                        <span>Logout</span>
                    </button>
                </div>
            </aside>
        </>
    );
};

const MainLayout: React.FC<{
    children: React.ReactNode;
    onNavClick: (page: string) => void;
    currentPage: string;
    onLogout: () => void;
    currentUser: User;
    onAdminClick: () => void;
}> = ({ children, onNavClick, currentPage, onLogout, currentUser, onAdminClick }) => {
    const [isSidebarOpen, setIsSidebarOpen] = useState(false);
    
    return (
        <div className="min-h-screen flex flex-col">
            <div className="flex justify-between items-center px-4 pt-12 pb-4">
                 <div className="text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-accent-special to-accent-primary">
                    FundMind
                </div>
                <div className="flex items-center gap-2">
                    {currentPage !== 'dashboard' && (
                        <button onClick={() => onNavClick('dashboard')} className="p-2 rounded-full hover:bg-white/10">
                            <CloseIcon className="w-6 h-6" />
                        </button>
                    )}
                    <div className="hidden md:flex">
                        <Sidebar
                            isOpen={true} // Always "open" on desktop
                            onClose={() => {}} // No-op
                            currentPage={currentPage}
                            onNavClick={onNavClick}
                            onLogout={onLogout}
                            isAdmin={currentUser.isAdmin}
                            onAdminClick={onAdminClick}
                        />
                    </div>
                    <button onClick={() => setIsSidebarOpen(true)} className="p-2 rounded-full hover:bg-white/10 md:hidden">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-6 h-6">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" />
                        </svg>
                    </button>
                </div>
            </div>
             {/* Mobile Sidebar (controlled by state) */}
             <div className="md:hidden">
                <Sidebar
                    isOpen={isSidebarOpen}
                    onClose={() => setIsSidebarOpen(false)}
                    currentPage={currentPage}
                    onNavClick={onNavClick}
                    onLogout={onLogout}
                    isAdmin={currentUser.isAdmin}
                    onAdminClick={onAdminClick}
                />
            </div>
            <main className="flex-grow overflow-y-auto">
                {children}
            </main>
        </div>
    );
};

// --- MAIN APP COMPONENT ---

const AppContent: React.FC = () => {
    const { currentUser, justLoggedIn, setJustLoggedIn, logout, addTransaction, isCreatingWallet, completeWalletCreation } = useAuth();
    const [isLoading, setIsLoading] = useState(true);
    const [page, setPage] = useState('dashboard');
    const [isAdminPanel, setIsAdminPanel] = useState(false);
    const [showAdminPasswordModal, setShowAdminPasswordModal] = useState(false);
    const [stayInAdminSystem, setStayInAdminSystem] = useState(false);

    const { assets, walletAssets, totalValue, isLoading: assetsLoading, realBalances } = useAssetData(currentUser, addTransaction);
    
    // Modals state
    const [isSendModalOpen, setIsSendModalOpen] = useState(false);
    const [isReceiveModalOpen, setIsReceiveModalOpen] = useState(false);
    const [isBuyModalOpen, setIsBuyModalOpen] = useState(false);
    const [isSellModalOpen, setIsSellModalOpen] = useState(false);
    const [isSwapModalOpen, setIsSwapModalOpen] = useState(false);
    const [isWelcomeModalOpen, setIsWelcomeModalOpen] = useState(false);
    const [receipt, setReceipt] = useState<Transaction | null>(null);
    const [showRecoveryPhraseModal, setShowRecoveryPhraseModal] = useState(false);
    const [showPinSetupModal, setShowPinSetupModal] = useState(false);
    
    useEffect(() => {
        // Handle initial app load
        const timer = setTimeout(() => setIsLoading(false), 2500);
        return () => clearTimeout(timer);
    }, []);
    
    useEffect(() => {
        if (justLoggedIn && currentUser) {
            if (!currentUser.pin) {
                const isNewRegistration = !localStorage.getItem('fundmind_remembered_email');
                if (isNewRegistration && currentUser.appRecoveryPhrase) {
                    setShowRecoveryPhraseModal(true);
                } else {
                     setShowPinSetupModal(true);
                }
            } else {
                 setIsWelcomeModalOpen(true);
            }
            setJustLoggedIn(false);
        }
    }, [justLoggedIn, currentUser, setJustLoggedIn]);
    
    const handleRecoveryPhraseConfirmed = () => {
        setShowRecoveryPhraseModal(false);
        if (currentUser && !currentUser.pin) {
            setShowPinSetupModal(true);
        }
    };

    const handlePinSetupComplete = () => {
        setShowPinSetupModal(false);
        setIsWelcomeModalOpen(true);
    };

    if (isLoading) {
        return <InitialLoader />;
    }
    
    if (isCreatingWallet) {
        return <WalletCreationAnimation onComplete={completeWalletCreation} />;
    }

    if (!currentUser) {
        return <LoginPage />;
    }
    
    const handleAdminClick = () => {
        if (stayInAdminSystem) {
            setIsAdminPanel(true);
        } else {
            setShowAdminPasswordModal(true);
        }
    };
    
    const handleAdminAuthSuccess = (stayInSystem: boolean) => {
        setShowAdminPasswordModal(false);
        setStayInAdminSystem(stayInSystem);
        setIsAdminPanel(true);
    };
    
    const handleDashboardAction = (action: 'send' | 'receive' | 'buy' | 'sell' | 'swap') => {
        switch (action) {
            case 'send': setIsSendModalOpen(true); break;
            case 'receive': setIsReceiveModalOpen(true); break;
            case 'buy': setIsBuyModalOpen(true); break;
            case 'sell': setIsSellModalOpen(true); break;
            case 'swap': setIsSwapModalOpen(true); break;
        }
    };

    if (isAdminPanel) {
        return (
            <div className="min-h-screen text-light-text flex flex-col">
                <header className="bg-dark-card p-4 flex justify-between items-center flex-shrink-0">
                    <h1 className="text-xl font-bold">FundMind Admin Panel</h1>
                    <button onClick={() => setIsAdminPanel(false)} className="flex items-center gap-2 bg-dark-border py-2 px-4 rounded-lg hover:bg-white/20 transition-colors">
                        <ExitAdminIcon className="w-5 h-5" />
                        <span>Exit Admin</span>
                    </button>
                </header>
                <AdminPanel />
            </div>
        );
    }
    
    const renderPage = () => {
        if (assetsLoading && page === 'dashboard') {
            return <div className="flex justify-center items-center h-full pt-20"><Spinner className="w-12 h-12" /></div>;
        }
        switch (page) {
            case 'dashboard': return <Dashboard assets={assets} walletAssets={walletAssets} totalValue={totalValue} setPage={setPage} onActionClick={handleDashboardAction} />;
            case 'transactions': return <Transactions assets={assets} />;
            case 'profile': return <Profile walletAssets={walletAssets} />;
            case 'chat': return <Chat />;
            case 'markets': return <Markets assets={assets} />;
            case 'invest': return <InvestmentPlatform walletAssets={walletAssets} />;
            default: return <Dashboard assets={assets} walletAssets={walletAssets} totalValue={totalValue} setPage={setPage} onActionClick={handleDashboardAction} />;
        }
    };
    
    return (
        <>
            <MainLayout
                currentUser={currentUser}
                currentPage={page}
                onNavClick={setPage}
                onLogout={logout}
                onAdminClick={handleAdminClick}
            >
                <AnimatedPage key={page}>
                    {renderPage()}
                </AnimatedPage>
            </MainLayout>
            
             {/* Modals */}
            <SendModal 
                isOpen={isSendModalOpen}
                onClose={() => setIsSendModalOpen(false)}
                walletAssets={walletAssets}
                realBalances={realBalances}
                onTransactionInitiated={(tx) => setReceipt(tx)}
            />
            <ReceiveModal 
                isOpen={isReceiveModalOpen}
                onClose={() => setIsReceiveModalOpen(false)}
                address={currentUser.walletAddress}
                walletAssets={walletAssets}
            />
            <BuySellModal 
                isOpen={isBuyModalOpen}
                onClose={() => setIsBuyModalOpen(false)}
                walletAssets={walletAssets}
                mode="Buy"
            />
            <BuySellModal 
                isOpen={isSellModalOpen}
                onClose={() => setIsSellModalOpen(false)}
                walletAssets={walletAssets}
                mode="Sell"
            />
             <SwapModal
                isOpen={isSwapModalOpen}
                onClose={() => setIsSwapModalOpen(false)}
                assets={assets}
                walletAssets={walletAssets}
            />
            <WelcomeModal 
                isOpen={isWelcomeModalOpen} 
                onClose={() => setIsWelcomeModalOpen(false)} 
                username={currentUser.username} 
            />
             <TransactionReceiptModal 
                isOpen={!!receipt}
                onClose={() => setReceipt(null)}
                receipt={receipt}
                assets={assets}
            />
            <RecoveryPhraseModal 
                isOpen={showRecoveryPhraseModal}
                onClose={handleRecoveryPhraseConfirmed}
                phrase={currentUser.appRecoveryPhrase || ''}
            />
            <PinSetupModal
                isOpen={showPinSetupModal}
                onClose={handlePinSetupComplete}
            />
             <AdminPasswordModal 
                isOpen={showAdminPasswordModal}
                onClose={() => setShowAdminPasswordModal(false)}
                onSuccess={handleAdminAuthSuccess}
            />
        </>
    );
};

const App: React.FC = () => {
    return (
        <AuthProvider>
            <AppContent />
        </AuthProvider>
    );
};

export default App;
