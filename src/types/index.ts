// Policy Parser Types

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ComplianceFramework = 'SOC2' | 'ISO27001' | 'HIPAA' | 'GDPR' | 'PCI-DSS' | 'CUSTOM';
export type PolicyStatus = 'active' | 'draft' | 'archived' | 'superseded';

export interface Policy {
  id: string;
  name: string;
  description: string;
  framework: ComplianceFramework;
  status: PolicyStatus;
  version: string;
  requirements: PolicyRequirement[];
  controls: Control[];
  metadata: PolicyMetadata;
  content: string;
  parsedAt: Date;
}

export interface PolicyRequirement {
  id: string;
  description: string;
  category: string;
  mandatory: boolean;
  relatedControls: string[];
  severity: SeverityLevel;
}

export interface Control {
  id: string;
  name: string;
  description: string;
  implementation: string;
  tested: boolean;
  lastTested?: Date;
  testResult?: 'pass' | 'fail' | 'not_tested';
}

export interface PolicyMetadata {
  owner: string;
  department: string;
  effectiveDate: Date;
  reviewDate: Date;
  tags: string[];
  attachments: string[];
}
