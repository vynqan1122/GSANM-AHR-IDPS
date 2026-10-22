import React, { useEffect } from 'react';
import { X } from 'lucide-react';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  width?: 'md' | 'lg' | 'xl' | 'full';
  drawer?: boolean;
}

export function Modal({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  width = 'lg',
  drawer = false,
}: ModalProps) {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="soc-modal-backdrop" onClick={onClose}>
      <div
        className={`soc-modal-content modal-${width} ${drawer ? 'is-drawer' : ''}`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="soc-modal-header">
          <div>
            <h3 className="soc-modal-title">{title}</h3>
            {subtitle && <p className="soc-modal-subtitle">{subtitle}</p>}
          </div>
          <button className="soc-modal-close-btn" onClick={onClose} aria-label="Đóng">
            <X size={18} />
          </button>
        </div>
        <div className="soc-modal-body">{children}</div>
      </div>
    </div>
  );
}
