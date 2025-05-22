import React, { useState, useEffect } from 'react';
import { Check, ChevronDown, Globe } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { AVAILABLE_LANGUAGES, i18n } from '@/lib/i18n';

// This is a simplified version of the language selector without hooks to prevent issues
export function LanguageSelectorSimple() {
  // Use direct DOM for language changes instead of React state
  const currentLanguage = i18n.getLanguage();
  
  const handleLanguageSelect = (lang: string) => {
    i18n.setLanguage(lang);
    // Force reload the page to apply changes
    window.location.reload();
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="h-8 gap-1 px-2">
          <Globe className="h-4 w-4" />
          <span className="hidden md:inline-flex">
            {AVAILABLE_LANGUAGES[currentLanguage as keyof typeof AVAILABLE_LANGUAGES]}
          </span>
          <ChevronDown className="h-4 w-4 opacity-50" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-[160px]">
        {Object.entries(AVAILABLE_LANGUAGES).map(([code, name]) => (
          <DropdownMenuItem 
            key={code}
            onClick={() => handleLanguageSelect(code)}
            className="flex justify-between items-center cursor-pointer"
          >
            {name}
            {currentLanguage === code && (
              <Check className="h-4 w-4 text-primary" />
            )}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}