import React from 'react';
import { cn } from '../../lib/utils';

const Button = ({ children, variant = 'default', size = 'default', className, ...props }) => {
    const variants = {
        default: "bg-neon-green/10 text-neon-green border-neon-green hover:bg-neon-green hover:text-black hover:shadow-[0_0_15px_rgba(0,255,65,0.4)]",
        destructive: "bg-neon-red/10 text-neon-red border-neon-red hover:bg-neon-red hover:text-black hover:shadow-[0_0_15px_rgba(255,0,60,0.4)]",
        ghost: "bg-transparent text-gray-400 border-transparent hover:text-neon-cyan hover:bg-white/5",
        outline: "bg-transparent text-neon-cyan border-neon-cyan hover:bg-neon-cyan/10",
    };

    const sizes = {
        default: "h-9 px-4 py-2",
        sm: "h-7 px-2 text-xs",
        lg: "h-11 px-8 text-base",
        icon: "h-9 w-9 p-0 flex items-center justify-center",
    };

    return (
        <button
            className={cn(
                "inline-flex items-center justify-center font-mono font-bold uppercase tracking-wider transition-all duration-200 border",
                "focus:outline-none focus:ring-1 focus:ring-offset-1 focus:ring-offset-black",
                "disabled:opacity-50 disabled:pointer-events-none",
                "relative overflow-hidden",
                variants[variant],
                sizes[size],
                className
            )}
            {...props}
        >
            <span className="relative z-10 flex items-center gap-2">{children}</span>
        </button>
    );
};

export default Button;
