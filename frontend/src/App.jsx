import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import Scanner from './pages/Scanner';
import ScanHistory from './pages/ScanHistory';
import Vulnerabilities from './pages/Vulnerabilities';
import AIAssistant from './pages/AIAssistant';
import Settings from './pages/Settings';

export function App() {
  const [activeTab, setActiveTab] = useState('scanner'); // Default to Scanner as requested in prompt & visual reference
  const [assistantScanId, setAssistantScanId] = useState(null);

  const handleNavigateToScanner = () => {
    setActiveTab('scanner');
  };

  const handleNavigateToAssistant = (scanId) => {
    setAssistantScanId(scanId);
    setActiveTab('assistant');
  };

  const handleOpenScanDetail = (scanId) => {
    // Navigate to scanner with that scan
    setActiveTab('scanner');
  };

  return (
    <div className="flex min-h-screen bg-[#080c14] text-slate-100 font-sans">
      {/* Left Sidebar matching Screenshot */}
      <Sidebar activeTab={activeTab} onSelectTab={setActiveTab} />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <Navbar onQuickScan={handleNavigateToScanner} activeTab={activeTab} />

        <main className="flex-1 p-6 md:p-8 overflow-y-auto">
          {activeTab === 'dashboard' && (
            <Dashboard
              onNavigateToScanner={handleNavigateToScanner}
              onNavigateToScanDetail={handleOpenScanDetail}
            />
          )}

          {activeTab === 'scanner' && (
            <Scanner onNavigateToAssistant={handleNavigateToAssistant} />
          )}

          {activeTab === 'history' && (
            <ScanHistory onOpenScanDetail={handleOpenScanDetail} />
          )}

          {activeTab === 'vulnerabilities' && (
            <Vulnerabilities />
          )}

          {activeTab === 'assistant' && (
            <AIAssistant initialScanId={assistantScanId} />
          )}

          {activeTab === 'settings' && (
            <Settings />
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
