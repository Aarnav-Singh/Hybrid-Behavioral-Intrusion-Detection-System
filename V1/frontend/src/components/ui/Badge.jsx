import React from 'react';
import { cn } from '../../lib/utils';

const Badge = ({ children, variant = 'default', className }) => {
    const variants = {
        default: "border-neon-cyan text-neon-cyan bg-neon-cyan/10",
        success: "border-neon-green text-neon-green bg-neon-green/10",
        warning: "border-neon-yellow text-neon-yellow bg-neon-yellow/10",
        critical: "border-neon-red text-neon-red bg-neon-red/10 animate-pulse-glow",
        high: "border-orange-500 text-orange-500 bg-orange-500/10",
        low: "border-blue-400 text-blue-400 bg-blue-400/10",
    };

    // Map severity strings to variants
    const getVariant = (v) => {
        if (variants[v]) return variants[v];
        const lower = v?.toLowerCase();
        if (lower === 'critical') return variants.critical;
        if (lower === 'high') return variants.high; // or warning
        if (lower === 'medium') return variants.warning;
        if (lower === 'low') return variants.low;
        if (lower === 'active') return variants.default; // or warning
        if (lower === 'blocked') return variants.critical; // red
        if (lower === 'resolved') return variants.success;
        return variants.default;
    };

    return (
        <span className={cn(
            "px-1.5 py-0.5 text-[10px] uppercase tracking-widest font-bold border font-mono inline-flex items-center",
            getVariant(variant),
            className
        )}>
            {children}
        </span>
    );
};

export default Badge;
