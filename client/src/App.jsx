// client/src/App.jsx
import React, { useState, useEffect, useRef } from 'react';
import { initNoir, generateProof, verifyProof } from './zkService';
import { generateCombinedTestInputs } from './test/validTestData.js';
import './App.css';

function App() {
  const [logs, setLogs] = useState([]);
  const [isInitialized, setIsInitialized] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [proofData, setProofData] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [animationFrame, setAnimationFrame] = useState(0);
  const [activeAnimationIds, setActiveAnimationIds] = useState(new Set());
  const [loadingProgress, setLoadingProgress] = useState(0);
  const [isInitializing, setIsInitializing] = useState(false);
  const [currentStage, setCurrentStage] = useState('idle');
  const [stageTimings, setStageTimings] = useState({});
  const [completedStages, setCompletedStages] = useState(new Set());
  const [showResultAnimation, setShowResultAnimation] = useState(false);
  const logsEndRef = useRef(null);
  const animationIntervalRef = useRef(null);

  // Processing animation symbols
  const processingSymbols = ['[◐]', '[◓]', '[◑]', '[◒]'];
  const loadingSymbols = ['[⁅]', '[⁆]', '[⌈]', '[⌉]', '[⌊]', '[⌋]'];
  
  const formatTime = (ms) => {
    if (ms < 1000) {
      return `${Math.round(ms * 10) / 10}ms`;
    }
    return `${(ms / 1000).toFixed(2)}s`;
  };

  const addLog = (message, type = 'info', id = null) => {
    const timestamp = new Date().toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit',
      fractionalSecondDigits: 3 
    });
    
    // If this is a completion of a processing log, stop its animation
    if (id && type !== 'processing') {
      setActiveAnimationIds(prev => {
        const newSet = new Set(prev);
        newSet.delete(id);
        return newSet;
      });
    }
    
    // Start new animation for processing logs
    if (type === 'processing' && id) {
      setActiveAnimationIds(prev => new Set(prev).add(id));
    }
    
    setLogs(prev => {
      const newLogs = [...prev];
      if (id && newLogs.some(log => log.id === id)) {
        return newLogs.map(log => 
          log.id === id ? { ...log, message, type, timestamp } : log
        );
      }
      return [...newLogs, { timestamp, message, type, id: id || Date.now() }];
    });
  };

  useEffect(() => {
    // Animate processing symbols for active animations
    if (activeAnimationIds.size > 0) {
      animationIntervalRef.current = setInterval(() => {
        setAnimationFrame(prev => (prev + 1) % processingSymbols.length);
      }, 150);
    } else {
      clearInterval(animationIntervalRef.current);
    }
    return () => clearInterval(animationIntervalRef.current);
  }, [activeAnimationIds]);

  useEffect(() => {
    // Auto-scroll to latest log
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  useEffect(() => {
    async function initialize() {
      try {
        setIsInitializing(true);
        setLoadingProgress(0);
        addLog('System initializing...', 'system');
        
        // Simulate loading progress
        const progressInterval = setInterval(() => {
          setLoadingProgress(prev => Math.min(prev + 10, 90));
        }, 200);
        
        addLog('Loading Noir compiler & backend...', 'system');
        
        await initNoir();
        
        clearInterval(progressInterval);
        setLoadingProgress(100);
        
        setTimeout(() => {
          setIsInitializing(false);
          setIsInitialized(true);
          addLog('[+] Noir & Backend initialized', 'success');
          addLog('System ready for proof generation', 'success');
        }, 300);
      } catch (error) {
        setIsInitializing(false);
        addLog(`[×] Initialization failed: ${error.message}`, 'error');
        console.error("Initialization error:", error);
      }
    }
    initialize();
  }, []);

  const handleProveDeletion = async () => {
    if (!isInitialized) {
      addLog('[!] System not yet initialized', 'warning');
      return;
    }

    setIsProcessing(true);
    setProofData(null);
    setVerificationResult(null);
    setShowResultAnimation(false);
    setStageTimings({});
    setCompletedStages(new Set());
    
    const startTime = performance.now();
    let stageStartTime = performance.now();
    
    addLog('Starting proof generation sequence...', 'info');
    setCurrentStage('preparing');
    
    const prepareId = Date.now();
    addLog('Preparing circuit inputs...', 'processing', prepareId);
    
    let inputsForProof;

    try {
      inputsForProof = await generateCombinedTestInputs();
      
      const prepareTime = performance.now() - stageStartTime;
      setStageTimings(prev => ({ ...prev, prepare: prepareTime }));
      setCompletedStages(prev => new Set(prev).add('preparing'));
      
      addLog(`[+] Inputs prepared successfully (${formatTime(prepareTime)})`, 'success', prepareId);
      
      setCurrentStage('validating');
      stageStartTime = performance.now();
      const validateId = Date.now();
      addLog('Input validation...', 'processing', validateId);

      if (!inputsForProof || Object.keys(inputsForProof).length === 0) {
        addLog('[×] Input validation failed: empty inputs', 'error', validateId);
        setIsProcessing(false);
        setCurrentStage('failed');
        return;
      }
      
      if (!inputsForProof.hasOwnProperty('payload_base64_decode_offset')) {
        addLog('[×] Missing JWT payload offset', 'error', validateId);
        setIsProcessing(false);
        setCurrentStage('failed');
        return;
      }
      
      if (!inputsForProof.hasOwnProperty('current_nmt_root')) {
        addLog('[×] Missing NMT root', 'error', validateId);
        setIsProcessing(false);
        setCurrentStage('failed');
        return;
      }

      const validateTime = performance.now() - stageStartTime;
      setStageTimings(prev => ({ ...prev, validate: validateTime }));
      setCompletedStages(prev => new Set(prev).add('validating'));
      
      addLog(`[+] Input validation passed (${formatTime(validateTime)})`, 'success', validateId);
      
      setCurrentStage('executing');
      stageStartTime = performance.now();
      const executeId = Date.now();
      addLog('Executing Noir circuit...', 'processing', executeId);
      
      const generatedProofObject = await generateProof(inputsForProof);
      
      const executeTime = performance.now() - stageStartTime;
      setStageTimings(prev => ({ ...prev, execute: executeTime }));
      setCompletedStages(prev => new Set(prev).add('executing'));
      
      addLog(`[+] Proof generated successfully (${formatTime(executeTime)})`, 'success', executeId);
      setProofData(generatedProofObject);
      
      setCurrentStage('verifying');
      stageStartTime = performance.now();
      const verifyId = Date.now();
      addLog('Starting proof verification...', 'processing', verifyId);
      
      const isValid = await verifyProof(generatedProofObject);
      
      const verifyTime = performance.now() - stageStartTime;
      const totalTime = performance.now() - startTime;
      setStageTimings(prev => ({ ...prev, verify: verifyTime, total: totalTime }));
      setCompletedStages(prev => new Set(prev).add('verifying'));
      
      setVerificationResult(isValid);
      setCurrentStage(isValid ? 'valid' : 'invalid');
      
      addLog(
        isValid 
          ? `[+] Proof verified: VALID (${formatTime(verifyTime)})` 
          : `[×] Proof verification: INVALID (${formatTime(verifyTime)})`, 
        isValid ? 'success' : 'error',
        verifyId
      );
      
      addLog(`Total execution time: ${formatTime(totalTime)}`, 'info');
      
      // Show result animation
      setShowResultAnimation(true);
      setTimeout(() => setShowResultAnimation(false), 1000);
      
    } catch (error) {
      addLog(`[×] ZK operation failed: ${error.message}`, 'error');
      console.error("ZK Operation Error:", error);
      setVerificationResult(false);
      setCurrentStage('failed');
    } finally {
      setIsProcessing(false);
    }
  };

  const getLogSymbol = (type, logId) => {
    switch(type) {
      case 'success': return '[+]';
      case 'error': return '[×]';
      case 'warning': return '[!]';
      case 'processing': 
        return activeAnimationIds.has(logId) ? processingSymbols[animationFrame] : '[▣]';
      case 'system': return '[◆]';
      default: return '[▸]';
    }
  };

  const getLogClass = (type) => {
    switch(type) {
      case 'success': return 'log-success';
      case 'error': return 'log-error';
      case 'warning': return 'log-warning';
      case 'processing': return 'log-processing';
      case 'system': return 'log-system';
      default: return 'log-info';
    }
  };

  const getStageIcon = (stageName, isActive, isCompleted) => {
    if (isCompleted) {
      if (stageName === 'preparing') return '[✓]';
      if (stageName === 'validating') return '[✓]';
      if (stageName === 'executing') return '[✓]';
      if (stageName === 'verifying') return '[✓]';
      if (stageName === 'result') {
        if (currentStage === 'valid') return '[+]';
        if (currentStage === 'invalid' || currentStage === 'failed') return '[×]';
      }
    }
    
    if (isActive) {
      if (stageName === 'preparing') return '[◐]';
      if (stageName === 'validating') return '[◑]';
      if (stageName === 'executing') return '[◒]';
      if (stageName === 'verifying') return '[◓]';
    }
    
    // Stage-specific idle icons
    if (stageName === 'preparing') return '[□]';
    if (stageName === 'validating') return '[◇]';
    if (stageName === 'executing') return '[○]';
    if (stageName === 'verifying') return '[◊]';
    if (stageName === 'result') return '[⬚]';
    
    return '[◯]';
  };

  const getStageColor = (stageName, isActive, isCompleted) => {
    if (isCompleted) {
      if (stageName === 'result') {
        if (currentStage === 'valid') return 'var(--success)';
        if (currentStage === 'invalid' || currentStage === 'failed') return 'var(--error)';
      }
      return 'var(--success)';
    }
    if (isActive) return 'var(--accent)';
    return 'var(--text-tertiary)';
  };

  return (
    <div className="app-container">
      <div className="app-card">
        <h1>
          <span className="title-symbol">[◆]</span> 
          Ephemeral Echo - ZK Deletion Proof Test 
          <span className="title-subtitle">(with kit merkle + jwt auth)</span>
        </h1>
        
        <div className="control-panel">
          <button
            onClick={handleProveDeletion}
            disabled={!isInitialized || isProcessing}
            className="proof-button"
          >
            {isProcessing ? (
              <>
                <span className="button-icon">{loadingSymbols[animationFrame % loadingSymbols.length]}</span>
                Processing...
              </>
            ) : (
              <>
                <span className="button-icon">[▸]</span>
                Generate Combined Proof
              </>
            )}
          </button>
          {isInitializing && (
            <div className="loading-bar">
              <div className="loading-progress" style={{ width: `${loadingProgress}%` }} />
            </div>
          )}
        </div>

        <div className="stage-flow">
          <div className="stage-item">
            <span className="stage-icon" style={{ color: getStageColor('preparing', currentStage === 'preparing', completedStages.has('preparing')) }}>
              {getStageIcon('preparing', currentStage === 'preparing', completedStages.has('preparing'))}
            </span>
            <span className="stage-label">Prepare</span>
            {stageTimings.prepare && <span className="stage-time">{formatTime(stageTimings.prepare)}</span>}
          </div>
          <span className="stage-arrow">[→]</span>
          <div className="stage-item">
            <span className="stage-icon" style={{ color: getStageColor('validating', currentStage === 'validating', completedStages.has('validating')) }}>
              {getStageIcon('validating', currentStage === 'validating', completedStages.has('validating'))}
            </span>
            <span className="stage-label">Validate</span>
            {stageTimings.validate && <span className="stage-time">{formatTime(stageTimings.validate)}</span>}
          </div>
          <span className="stage-arrow">[→]</span>
          <div className="stage-item">
            <span className="stage-icon" style={{ color: getStageColor('executing', currentStage === 'executing', completedStages.has('executing')) }}>
              {getStageIcon('executing', currentStage === 'executing', completedStages.has('executing'))}
            </span>
            <span className="stage-label">Execute</span>
            {stageTimings.execute && <span className="stage-time">{formatTime(stageTimings.execute)}</span>}
          </div>
          <span className="stage-arrow">[→]</span>
          <div className="stage-item">
            <span className="stage-icon" style={{ color: getStageColor('verifying', currentStage === 'verifying', completedStages.has('verifying')) }}>
              {getStageIcon('verifying', currentStage === 'verifying', completedStages.has('verifying'))}
            </span>
            <span className="stage-label">Verify</span>
            {stageTimings.verify && <span className="stage-time">{formatTime(stageTimings.verify)}</span>}
          </div>
          <span className="stage-arrow">[→]</span>
          <div className="stage-item">
            <span className="stage-icon" style={{ color: getStageColor('result', false, currentStage === 'valid' || currentStage === 'invalid') }}>
              {getStageIcon('result', false, currentStage === 'valid' || currentStage === 'invalid')}
            </span>
            <span className="stage-label">Result</span>
          </div>
        </div>

        <div className="terminal-container">
          <div className="terminal-header">
            <span className="terminal-title">[◊] System Log</span>
            <span className="terminal-status">
              {isProcessing ? `${processingSymbols[animationFrame]} Processing` : '[●] Ready'}
            </span>
          </div>
          <div className="terminal-body">
            {logs.map((log) => (
              <div key={log.id} className={`log-entry ${getLogClass(log.type)}`}>
                <span className="log-timestamp">[{log.timestamp}]</span>
                <span className="log-symbol">{getLogSymbol(log.type, log.id)}</span>
                <span className="log-message">{log.message}</span>
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        </div>

        {verificationResult !== null && (
          <div className={`result-card ${verificationResult ? 'result-valid' : 'result-invalid'} ${showResultAnimation ? 'result-animation' : ''}`}>
            <span className="result-icon">{verificationResult ? '[+]' : '[×]'}</span>
            <span className="result-text">
              Verification Result: {verificationResult ? 'VALID' : 'INVALID'}
            </span>
            {stageTimings.total && (
              <span className="result-time">Total: {formatTime(stageTimings.total)}</span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;