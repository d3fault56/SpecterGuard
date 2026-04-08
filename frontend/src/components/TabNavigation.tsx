'use client';

interface TabNavigationProps {
  currentTab: 'text' | 'email' | 'url';
  onTabChange: (tab: 'text' | 'email' | 'url') => void;
}

export default function TabNavigation({ currentTab, onTabChange }: TabNavigationProps) {
  const tabs = [
    { id: 'text', label: '📝 Text', name: 'SMS / Text Message' },
    { id: 'email', label: '📧 Email', name: 'Email' },
    { id: 'url', label: '🌐 URL', name: 'Website URL' },
  ] as const;

  return (
    <div className="tabs">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          className={`tab-btn ${currentTab === tab.id ? 'active' : ''}`}
          onClick={() => onTabChange(tab.id)}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
