import {
  Activity,
  BarChart3,
  Boxes,
  Braces,
  Cloud,
  Code2,
  Cookie,
  CreditCard,
  Database,
  FileCode2,
  FileText,
  Globe,
  Layers,
  LayoutTemplate,
  Lock,
  MessageSquare,
  Server,
  Shield,
  ShoppingCart,
  Tags,
  Type,
  Wrench,
  Puzzle,
  Cpu,
  Megaphone,
  Shapes,
  type LucideIcon,
} from 'lucide-react';
import type { CategoryId } from '../../types';

export const CATEGORY_ICON: Record<CategoryId, LucideIcon> = {
  'js-framework': Layers,
  'js-library': Code2,
  'ui-framework': LayoutTemplate,
  cms: FileText,
  ecommerce: ShoppingCart,
  analytics: BarChart3,
  'tag-manager': Tags,
  cdn: Globe,
  waf: Shield,
  security: Lock,
  'web-server': Server,
  language: Braces,
  'web-framework': Boxes,
  paas: Cloud,
  ssg: FileCode2,
  font: Type,
  payment: CreditCard,
  widget: MessageSquare,
  monitoring: Activity,
  'build-tool': Wrench,
  cache: Database,
  consent: Cookie,
  'cms-extension': Puzzle,
  database: Database,
  os: Cpu,
  marketing: Megaphone,
  other: Shapes,
};

/** TechRecon mark: a reticle. Same drawing as the toolbar icon. */
export function Logo({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <rect x="1.5" y="1.5" width="29" height="29" rx="7" fill="var(--surface-2)" stroke="var(--accent)" strokeWidth="1.5" />
      <circle cx="16" cy="16" r="7.5" fill="none" stroke="var(--accent)" strokeWidth="2" />
      <path d="M16 4.5v5M16 22.5v5M4.5 16h5M22.5 16h5" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" />
      <circle cx="16" cy="16" r="2.2" fill="var(--text)" />
    </svg>
  );
}
