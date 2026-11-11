import React from 'react';
import { PAFieldInspector } from './PAFieldInspector';
import { ForensicProvenance, TimestampTriplet } from '../../shared/forensic-types';

interface ProvenanceSidebarProps {
  provenance?: ForensicProvenance | null;
  timestamp?: TimestampTriplet | null;
  embeddedIdTimestamp?: TimestampTriplet | null;
  clockTamperDetected?: boolean;
  notes?: string;
}

export const ProvenanceSidebar: React.FC<ProvenanceSidebarProps> = (props) => {
  return <PAFieldInspector {...props} />;
};

export { PAFieldInspector };
