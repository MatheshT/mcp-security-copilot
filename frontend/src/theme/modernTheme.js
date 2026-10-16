// =============================================
// SENTINELAI X — Design System Tokens (JS)
// Premium Cybersecurity Command Center Theme
// =============================================

export const MODERN_COLORS = {
  // Backgrounds
  background: '#060910',
  backgroundDeep: '#04060d',
  surface: '#0c1120',
  surfaceLight: '#111827',
  elevated: '#1a2236',
  hover: '#243044',

  // Glass
  glass: 'rgba(12, 17, 32, 0.75)',
  glassLight: 'rgba(30, 41, 59, 0.5)',
  glassDark: 'rgba(4, 6, 13, 0.9)',
  glassBorder: 'rgba(255, 255, 255, 0.06)',
  glassBorderLight: 'rgba(255, 255, 255, 0.1)',

  // Text
  text: '#a5f3fc',
  textSecondary: '#67e8f9',
  textMuted: '#22d3ee',
  textDim: '#06b6d4',
  textBright: '#ffffff',

  // Primary
  primary: '#6366f1',
  primaryLight: '#818cf8',
  primaryDark: '#4f46e5',

  // Accents
  violet: '#8b5cf6',
  cyan: '#06b6d4',
  teal: '#14b8a6',
  blue: '#3b82f6',
  purple: '#a855f7',

  // Status
  success: '#10b981',
  successLight: '#34d399',
  warning: '#f59e0b',
  warningLight: '#fbbf24',
  danger: '#ef4444',
  dangerLight: '#f87171',
  info: '#3b82f6',
  infoLight: '#60a5fa',

  // Severity
  critical: '#dc2626',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',

  // Gradients
  gradientPrimary: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
  primaryGradient: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
  gradientAccent: 'linear-gradient(135deg, #6366f1, #8b5cf6, #06b6d4)',
  gradientCyan: 'linear-gradient(135deg, #06b6d4, #14b8a6)',
  gradientDanger: 'linear-gradient(135deg, #ef4444, #dc2626)',
  gradientSuccess: 'linear-gradient(135deg, #10b981, #059669)',
  gradientWarning: 'linear-gradient(135deg, #f59e0b, #d97706)',
  gradientAurora: 'linear-gradient(135deg, #6366f1, #8b5cf6, #06b6d4, #14b8a6)',
  gradientMidnight: 'linear-gradient(135deg, #0c1120, #1a2236, #0c1120)',
  gradientSubtle: 'linear-gradient(135deg, rgba(99,102,241,0.1), rgba(139,92,246,0.05))',

  // Shadows
  shadowLight: '0 4px 16px rgba(0, 0, 0, 0.1)',
  shadowMedium: '0 8px 24px rgba(0, 0, 0, 0.15)',
  shadowHeavy: '0 16px 48px rgba(0, 0, 0, 0.2)',
};

export const SEVERITY_CONFIG = {
  critical: {
    color: '#dc2626', bg: 'rgba(220, 38, 38, 0.12)', border: 'rgba(220, 38, 38, 0.4)',
    gradient: 'linear-gradient(135deg, #dc2626, #b91c1c)', glow: '0 0 12px rgba(220, 38, 38, 0.4)', label: 'Critical',
  },
  high: {
    color: '#f97316', bg: 'rgba(249, 115, 22, 0.12)', border: 'rgba(249, 115, 22, 0.4)',
    gradient: 'linear-gradient(135deg, #f97316, #ea580c)', glow: '0 0 12px rgba(249, 115, 22, 0.4)', label: 'High',
  },
  medium: {
    color: '#eab308', bg: 'rgba(234, 179, 8, 0.12)', border: 'rgba(234, 179, 8, 0.4)',
    gradient: 'linear-gradient(135deg, #eab308, #ca8a04)', glow: '0 0 12px rgba(234, 179, 8, 0.3)', label: 'Medium',
  },
  low: {
    color: '#22c55e', bg: 'rgba(34, 197, 94, 0.12)', border: 'rgba(34, 197, 94, 0.4)',
    gradient: 'linear-gradient(135deg, #22c55e, #16a34a)', glow: '0 0 12px rgba(34, 197, 94, 0.3)', label: 'Low',
  },
  info: {
    color: '#3b82f6', bg: 'rgba(59, 130, 246, 0.12)', border: 'rgba(59, 130, 246, 0.4)',
    gradient: 'linear-gradient(135deg, #3b82f6, #2563eb)', glow: '0 0 12px rgba(59, 130, 246, 0.3)', label: 'Info',
  },
};

export const ANIMATION_CONFIG = {
  duration: { fast: 150, normal: 300, slow: 500, slower: 800 },
  easing: {
    sharp: 'cubic-bezier(0.4, 0, 0.2, 1)',
    smooth: 'cubic-bezier(0.25, 0.8, 0.25, 1)',
    bounce: 'cubic-bezier(0.34, 1.56, 0.64, 1)',
    spring: 'cubic-bezier(0.175, 0.885, 0.32, 1.275)',
  },
  stagger: 0.05,
};

export const SPACING = { xs: 4, sm: 8, md: 12, lg: 16, xl: 20, xxl: 24, xxxl: 32, huge: 48 };
export const BORDER_RADIUS = { sm: 6, md: 8, lg: 12, xl: 16, xxl: 20, full: 9999 };
export const Z_INDEX = { dropdown: 100, sticky: 200, fixed: 300, modalBackdrop: 400, modal: 500, popover: 600, tooltip: 700, toast: 800 };

export const TYPOGRAPHY = {
  fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
  fontFamilyMono: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
  fontSize: {
    xs: '0.6875rem', sm: '0.75rem', base: '0.8125rem', md: '0.875rem',
    lg: '1rem', xl: '1.125rem', '2xl': '1.5rem', '3xl': '1.875rem', '4xl': '2.25rem', '5xl': '3rem',
  },
  fontWeight: { light: 300, normal: 400, medium: 500, semibold: 600, bold: 700, extrabold: 800 },
  letterSpacing: { tight: '-0.02em', normal: '0em', wide: '0.04em', wider: '0.08em' },
};

// --- Reusable Style Objects ---
export const glassCardStyle = {
  background: MODERN_COLORS.glass,
  backdropFilter: 'blur(20px)',
  WebkitBackdropFilter: 'blur(20px)',
  border: `1px solid ${MODERN_COLORS.glassBorder}`,
  borderRadius: BORDER_RADIUS.lg,
  transition: `all ${ANIMATION_CONFIG.duration.normal}ms ${ANIMATION_CONFIG.easing.smooth}`,
};

export const glassCardHoverStyle = {
  borderColor: MODERN_COLORS.glassBorderLight,
  boxShadow: '0 8px 32px rgba(0, 0, 0, 0.4)',
  transform: 'translateY(-2px)',
};

export const cardHoverStyle = glassCardHoverStyle;

export const modernButtonStyle = {
  background: MODERN_COLORS.gradientPrimary,
  color: '#ffffff',
  border: 'none',
  borderRadius: BORDER_RADIUS.md,
  padding: '8px 18px',
  fontFamily: TYPOGRAPHY.fontFamily,
  fontWeight: TYPOGRAPHY.fontWeight.medium,
  fontSize: TYPOGRAPHY.fontSize.base,
  cursor: 'pointer',
  transition: `all ${ANIMATION_CONFIG.duration.normal}ms ${ANIMATION_CONFIG.easing.smooth}`,
  boxShadow: '0 2px 8px rgba(99, 102, 241, 0.3)',
};

export const modernInputStyle = {
  background: MODERN_COLORS.surface,
  color: MODERN_COLORS.text,
  border: `1px solid ${MODERN_COLORS.glassBorder}`,
  borderRadius: BORDER_RADIUS.md,
  padding: '10px 14px',
  fontFamily: TYPOGRAPHY.fontFamily,
  fontSize: TYPOGRAPHY.fontSize.base,
  outline: 'none',
  transition: `all ${ANIMATION_CONFIG.duration.fast}ms ${ANIMATION_CONFIG.easing.sharp}`,
  width: '100%',
};

// --- Utility Functions ---
export const getStatusColor = (status) => {
  const map = {
    online: MODERN_COLORS.success, active: MODERN_COLORS.success, connected: MODERN_COLORS.success, healthy: MODERN_COLORS.success,
    completed: MODERN_COLORS.success, resolved: MODERN_COLORS.success,
    warning: MODERN_COLORS.warning, degraded: MODERN_COLORS.warning, pending: MODERN_COLORS.warning,
    investigating: MODERN_COLORS.warning, 'in progress': MODERN_COLORS.warning, 'in-progress': MODERN_COLORS.warning,
    offline: MODERN_COLORS.danger, error: MODERN_COLORS.danger, disconnected: MODERN_COLORS.danger,
    failed: MODERN_COLORS.danger, critical: MODERN_COLORS.danger,
    inactive: MODERN_COLORS.textMuted, unknown: MODERN_COLORS.textMuted, new: MODERN_COLORS.info,
    open: MODERN_COLORS.info, acknowledged: MODERN_COLORS.blue,
  };
  return map[status?.toLowerCase()] || MODERN_COLORS.textMuted;
};

export const getSeverityColor = (severity) => {
  return SEVERITY_CONFIG[severity?.toLowerCase()]?.color || MODERN_COLORS.textMuted;
};

export const getSeverityGradient = (severity) => {
  return SEVERITY_CONFIG[severity?.toLowerCase()]?.gradient || MODERN_COLORS.gradientPrimary;
};

export const getSeverityConfig = (severity) => {
  return SEVERITY_CONFIG[severity?.toLowerCase()] || SEVERITY_CONFIG.info;
};

export const formatNumber = (num) => {
  if (num === undefined || num === null) return '0';
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
  return num.toLocaleString();
};

export const timeSince = (date) => {
  if (!date) return 'Unknown';
  const now = new Date();
  const d = new Date(date);
  const seconds = Math.floor((now - d) / 1000);
  if (seconds < 0) return 'Just now';
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return d.toLocaleDateString();
};

export const truncateText = (text, maxLen = 50) => {
  if (!text) return '';
  return text.length > maxLen ? text.substring(0, maxLen) + '...' : text;
};

// --- Chart Theme ---
export const chartTheme = {
  colors: ['#6366f1', '#8b5cf6', '#06b6d4', '#14b8a6', '#3b82f6', '#a855f7', '#ec4899', '#f59e0b'],
  grid: { stroke: 'rgba(255, 255, 255, 0.04)', strokeDasharray: '3 3' },
  axis: { stroke: 'rgba(255, 255, 255, 0.1)', fontSize: 11, fill: '#64748b' },
  tooltip: {
    contentStyle: {
      background: 'rgba(12, 17, 32, 0.95)',
      border: '1px solid rgba(255, 255, 255, 0.1)',
      borderRadius: '8px',
      color: '#f1f5f9',
      boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5)',
      backdropFilter: 'blur(20px)',
      fontSize: '12px',
      padding: '8px 12px',
    },
    labelStyle: { color: '#94a3b8', fontWeight: 500, marginBottom: '4px' },
    itemStyle: { color: '#f1f5f9', fontSize: '12px', padding: '2px 0' },
  },
};

// --- Framer Motion Variants ---
export const motionVariants = {
  fadeInUp: {
    initial: { opacity: 0, y: 20 },
    animate: { opacity: 1, y: 0 },
    exit: { opacity: 0, y: -10 },
    transition: { duration: 0.4, ease: [0.25, 0.8, 0.25, 1] },
  },
  fadeIn: {
    initial: { opacity: 0 },
    animate: { opacity: 1 },
    exit: { opacity: 0 },
    transition: { duration: 0.3 },
  },
  scaleIn: {
    initial: { opacity: 0, scale: 0.95 },
    animate: { opacity: 1, scale: 1 },
    exit: { opacity: 0, scale: 0.95 },
    transition: { duration: 0.3, ease: [0.25, 0.8, 0.25, 1] },
  },
  slideInRight: {
    initial: { opacity: 0, x: 30 },
    animate: { opacity: 1, x: 0 },
    exit: { opacity: 0, x: 30 },
    transition: { duration: 0.3 },
  },
  staggerContainer: {
    animate: { transition: { staggerChildren: 0.06 } },
  },
  staggerItem: {
    initial: { opacity: 0, y: 15 },
    animate: { opacity: 1, y: 0 },
    transition: { duration: 0.35 },
  },
};

export default {
  MODERN_COLORS, SEVERITY_CONFIG, ANIMATION_CONFIG,
  SPACING, BORDER_RADIUS, TYPOGRAPHY, Z_INDEX,
  glassCardStyle, glassCardHoverStyle, cardHoverStyle,
  modernButtonStyle, modernInputStyle,
  getStatusColor, getSeverityColor, getSeverityGradient, getSeverityConfig,
  formatNumber, timeSince, truncateText,
  chartTheme, motionVariants,
};