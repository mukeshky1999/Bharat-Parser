import {
  Home, MessagesSquare, IndianRupee, MapPin, FolderOpen, Network, FileText,
  type LucideIcon,
} from 'lucide-react';
import type { ActiveTabType } from '../state/workbenchStore';

/** The colour family of a group. 'accent' is the case overview; the rest are the calm per-group hues. */
export type Hue = 'accent' | 'comm' | 'money' | 'places' | 'files' | 'analysis' | 'report';

export type GroupId = 'overview' | Exclude<Hue, 'accent'>;

export interface StageView {
  tab: ActiveTabType;
  label: string;
  /** When set, the view is shown greyed out and opens nothing; this text is shown instead. */
  unavailable?: string;
  /** When true, the view works and is marked "in testing" wherever it is listed and on its own screen. */
  inTesting?: boolean;
}

/** Shown on the bank alerts screen. */
export const BANK_ALERTS_NOTICE =
  'Bank alerts (bank and SMS notices such as debits, credits, freeze or lien notices and one-time codes) are read with rules that have been run on made-up data only. They have not yet been tested on real bank and SMS data, so treat them as leads.';

export interface Group {
  id: GroupId;
  no: number;
  label: string;
  hue: Hue;
  icon: LucideIcon;
  views: StageView[];
}

/** Seven groups: the case overview, then the data by kind, then analysis and the report. */
export const GROUPS: Group[] = [
  { id: 'overview', no: 1, label: 'Overview', hue: 'accent', icon: Home,
    views: [{ tab: 'SUMMARY', label: 'Case overview' }] },
  { id: 'comm', no: 2, label: 'Communication', hue: 'comm', icon: MessagesSquare,
    views: [{ tab: 'CHATS', label: 'Chats' }, { tab: 'CALLS', label: 'Calls' }, { tab: 'CONTACTS', label: 'Contacts' }] },
  { id: 'money', no: 3, label: 'Financial', hue: 'money', icon: IndianRupee,
    views: [
      { tab: 'UPI_LEDGER', label: 'UPI ledger' },
      { tab: 'CALL_LOGS', label: 'Bank & call records' },
      { tab: 'CRYPTO', label: 'Crypto wallets' },
      { tab: 'BANK_ALERTS', label: 'Bank alerts', inTesting: true },
    ] },
  { id: 'places', no: 4, label: 'Places & media', hue: 'places', icon: MapPin,
    views: [{ tab: 'LOCATIONS_MEDIA', label: 'Locations' }, { tab: 'MEDIA', label: 'Media library' }] },
  { id: 'files', no: 5, label: 'Files & data', hue: 'files', icon: FolderOpen,
    views: [{ tab: 'FILE_SYSTEM', label: 'Files' }, { tab: 'SQLITE_WIZARD', label: 'Database inspector' }, { tab: 'OS_SPILLOVER', label: 'System traces' }] },
  { id: 'analysis', no: 6, label: 'Analysis', hue: 'analysis', icon: Network,
    views: [
      { tab: 'SEARCH', label: 'Search records' },
      { tab: 'TIMELINE', label: 'Timeline' },
      { tab: 'MULE_GRAPH', label: 'Link graph (leads)' },
      { tab: 'TAGS', label: 'Tagged records' },
      { tab: 'FINDINGS', label: 'Pinned findings' },
    ] },
  { id: 'report', no: 7, label: 'Report', hue: 'report', icon: FileText,
    views: [{ tab: 'REPORT_EXPORT', label: 'Report & export' }] },
];

export function groupForTab(tab: ActiveTabType): Group {
  return GROUPS.find((g) => g.views.some((v) => v.tab === tab)) ?? GROUPS[0];
}

export function viewLabel(tab: ActiveTabType): string {
  for (const g of GROUPS) {
    const v = g.views.find((x) => x.tab === tab);
    if (v) return v.label;
  }
  return tab;
}

const COUNT_KEYS: Partial<Record<ActiveTabType, string>> = {
  CHATS: 'chats_all',
  CALLS: 'calls_all',
  CONTACTS: 'contacts_all',
  UPI_LEDGER: 'upi_all',
  CRYPTO: 'crypto_all',
  OS_SPILLOVER: 'os_spillover_all',
  LOCATIONS_MEDIA: 'locations_all',
  FILE_SYSTEM: 'vfs_files',
  SQLITE_WIZARD: 'data_files',
};

/** The key of caseSummary.counts that holds the record count of a view, if it has one. */
export function countKey(tab: ActiveTabType): string | null {
  return COUNT_KEYS[tab] ?? null;
}
