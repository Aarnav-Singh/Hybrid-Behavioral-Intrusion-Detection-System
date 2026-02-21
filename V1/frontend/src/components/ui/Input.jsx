import React from 'react';
import { cn } from '../../lib/utils';

const Input = React.forwardRef(({ className, ...props }, ref) => {
    return (
        <div className="relative group">
            <input
                className={cn(
                    "flex h-9 w-full bg-black/50 border-b-2 border-white/20 px-3 py-1 text-sm font-mono text-gray-200 shadow-sm transition-colors",
                    "placeholder:text-gray-600 focus-visible:outline-none focus:border-neon-cyan focus:bg-neon-cyan/5",
                    "disabled:cursor-not-allowed disabled:opacity-50",
                    className
                )}
                ref={ref}
                {...props}
            />
            {/* Focus Indicator */}
            <div className="absolute bottom-0 left-0 w-0 h-[2px] bg-neon-cyan transition-all duration-300 group-focus-within:w-full" />
        </div>
    );
});
Input.displayName = "Input";

export default Input;
