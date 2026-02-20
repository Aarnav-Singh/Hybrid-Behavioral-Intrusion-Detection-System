import React from 'react';
import { cn } from '../../lib/utils';

const Card = ({ children, className, title, action }) => {
    return (
        <div className={cn(
            "relative bg-black/40 border border-white/10 backdrop-blur-sm overflow-hidden group",
            "hover:border-neon-green/30 transition-colors duration-300",
            className
        )}>
            {/* Corner Accents */}
            <div className="absolute top-0 left-0 w-2 h-2 border-l-2 border-t-2 border-neon-green/50" />
            <div className="absolute top-0 right-0 w-2 h-2 border-r-2 border-t-2 border-neon-green/50" />
            <div className="absolute bottom-0 left-0 w-2 h-2 border-l-2 border-b-2 border-neon-green/50" />
            <div className="absolute bottom-0 right-0 w-2 h-2 border-r-2 border-b-2 border-neon-green/50" />

            {/* Header if title exists */}
            {(title || action) && (
                <div className="flex items-center justify-between px-4 py-3 border-b border-white/5 bg-white/5">
                    {title && (
                        <h3 className="font-display text-sm tracking-wider text-neon-green uppercase text-glow">
                            {title}
                        </h3>
                    )}
                    {action && <div>{action}</div>}
                </div>
            )}

            {/* Content */}
            <div className="p-4 relative z-10">
                {children}
            </div>

            {/* Scanline overlay for card */}
            <div className="absolute inset-0 pointer-events-none opacity-[0.02] bg-scanlines z-0" />
        </div>
    );
};

export default Card;
