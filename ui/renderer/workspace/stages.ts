import {
  FolderInput, HardDrive, Users, IndianRupee, MessagesSquare, MapPin, Pin, FileText,
  type LucideIcon,
} from 'lucide-react';
import type { ActiveTabType } from '../state/workbenchStore';

export type StageId = 'intake' | 'evidence' | 'people' | 'money' | 'messages' | 'places' | 'findings' | 'report';

export interface StageView {
  tab: ActiveTabType;
  label: string;
}

export interface Stage {
  id: StageId;
  no: number;
  label: string;
  /** one line shown under the stage name: what the examiner does here */
  hint: string;
  icon: LucideIcon;
  views: StageView[];
}

/** The eight stages follow the order of an investigation: bring evidence in, read it, decide what matters, then report and export what the software recorded. */
export const STAGES: Stage[] = [
  { id: 'intake', no: 1, label: 'Intake', hint: 'Open evidence, see what was read', icon: FolderInput,
    views: [{ tab: 'SUMMARY', label: 'Case overview' }] },
  { id: 'evidence', no: 2, label: 'Evidence', hint: 'Files, databases, integrity', icon: HardDrive,
    views: [{ tab: 'FILE_SYSTEM', label: 'Files' }, { tab: 'SQLITE_WIZARD', label: 'Database inspector' }, { tab: 'SEARCH', label: 'Search records' }] },
  { id: 'people', no: 3, label: 'People', hint: 'Contacts and calls', icon: Users,
    views: [{ tab: 'CONTACTS', label: 'Contacts' }, { tab: 'CALLS', label: 'Calls' }] },
  { id: 'money', no: 4, label: 'Money', hint: 'UPI, bank, crypto, links', icon: IndianRupee,
    views: [
      { tab: 'UPI_LEDGER', label: 'UPI ledger' },
      { tab: 'CALL_LOGS', label: 'Bank and call records' },
      { tab: 'CRYPTO', label: 'Crypto wallets' },
      { tab: 'MULE_GRAPH', label: 'Link graph (leads)' },
    ] },
  { id: 'messages', no: 5, label: 'Messages', hint: 'Chats and system traces', icon: MessagesSquare,
    views: [{ tab: 'CHATS', label: 'Chats' }, { tab: 'OS_SPILLOVER', label: 'System traces' }] },
  { id: 'places', no: 6, label: 'Places', hint: 'Locations, photos and videos', icon: MapPin,
    views: [{ tab: 'LOCATIONS_MEDIA', label: 'Locations' }, { tab: 'MEDIA', label: 'Media library' }] },
  { id: 'findings', no: 7, label: 'Findings', hint: 'What you pinned and tagged, and when', icon: Pin,
    views: [{ tab: 'FINDINGS', label: 'Pinned findings' }, { tab: 'TAGS', label: 'Tagged records' }, { tab: 'TIMELINE', label: 'Timeline' }] },
  { id: 'report', no: 8, label: 'Report & export', hint: 'Report, facts, review package, audit log', icon: FileText,
    views: [{ tab: 'REPORT_EXPORT', label: 'Report and export' }] },
];

export function stageForTab(tab: ActiveTabType): Stage {
  return STAGES.find((s) => s.views.some((v) => v.tab === tab)) ?? STAGES[0];
}

export function viewLabel(tab: ActiveTabType): string {
  for (const s of STAGES) {
    const v = s.views.find((x) => x.tab === tab);
    if (v) return v.label;
  }
  return tab;
}
