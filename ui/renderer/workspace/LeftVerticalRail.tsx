import React from 'react';
import {
  Home,
  Clock,
  Database,
  HardDrive,
  Lightbulb,
  Tag,
  FileCheck2,
  Cloud
} from 'lucide-react';
import { useWorkbenchStore, ActiveTabType } from '../state/workbenchStore';

export type RailItem =
  | 'Home'
  | 'Timeline'
  | 'Analyzed Data'
  | 'File Systems'
  | 'Insights'
  | 'Tags'
  | 'Reports'
  | 'Cloud';

interface LeftVerticalRailProps {
  activeRailItem: RailItem;
  onSelectRailItem: (item: RailItem) => void;
}

export const LeftVerticalRail: React.FC<LeftVerticalRailProps> = ({
  activeRailItem,
  onSelectRailItem,
}) => {
  const { setIsBsaModalOpen, setActiveTab } = useWorkbenchStore();

  const railButtons: Array<{ id: RailItem; label: string; icon: React.ReactNode; action: () => void }> = [
    {
      id: 'Home',
      label: 'Home',
      icon: <Home className="w-4 h-4" />,
      action: () => {
        onSelectRailItem('Home');
        setActiveTab('SUMMARY');
      }
    },
    {
      id: 'Timeline',
      label: 'Timeline',
      icon: <Clock className="w-4 h-4" />,
      action: () => {
        onSelectRailItem('Timeline');
        setActiveTab('CHATS');
      }
    },
    {
      id: 'Analyzed Data',
      label: 'Analyzed Data',
      icon: <Database className="w-4 h-4" />,
      action: () => {
        onSelectRailItem('Analyzed Data');
        setActiveTab('CHATS');
      }
    },
    {
      id: 'File Systems',
      label: 'File Systems',
      icon: <HardDrive className="w-4 h-4" />,
      action: () => {
        onSelectRailItem('File Systems');
        setActiveTab('FILE_SYSTEM');
      }
    },
    {
      id: 'Insights',
      label: 'Insights',
      icon: <Lightbulb className="w-4 h-4" />,
      action: () => {
        onSelectRailItem('Insights');
        setActiveTab('MULE_GRAPH');
      }
    },
    {
      id: 'Tags',
      label: 'Tags',
      icon: <Tag className="w-4 h-4" />,
      action: () => {
        onSelectRailItem('Tags');
      }
    },
    {
      id: 'Reports',
      label: 'Reports',
      icon: <FileCheck2 className="w-4 h-4" />,
      action: () => {
        onSelectRailItem('Reports');
        setIsBsaModalOpen(true);
      }
    },
    {
      id: 'Cloud',
      label: 'Cloud',
      icon: <Cloud className="w-4 h-4" />,
      action: () => {
        onSelectRailItem('Cloud');
      }
    },
  ];

  return (
    <aside className="w-[52px] bg-[#0b1120] border-r border-[#1e293b] flex flex-col items-center py-1 select-none shrink-0 z-40">
      {railButtons.map((btn) => {
        const isActive = activeRailItem === btn.id;
        return (
          <button
            key={btn.id}
            onClick={btn.action}
            title={btn.label}
            className={`w-[52px] h-[52px] flex flex-col items-center justify-center transition-colors cursor-pointer ${
              isActive
                ? 'bg-cyan-600 text-white font-semibold shadow-inner'
                : 'text-slate-400 hover:text-white hover:bg-slate-850'
            }`}
          >
            <div className="mb-1">{btn.icon}</div>
            <span className="text-[10px] leading-tight text-center px-0.5 truncate w-full">
              {btn.label}
            </span>
          </button>
        );
      })}
    </aside>
  );
};
