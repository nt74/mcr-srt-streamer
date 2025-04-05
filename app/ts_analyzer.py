import gi
gi.require_version('Gst', '1.0')
from gi.repository import Gst, GLib
import threading
import logging
import time
import json
from collections import defaultdict

class TSAnalyzer:
    """Analyzes TS streams for DVB compliance"""
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.analyzers = {}
        self.lock = threading.RLock()
        
    def start_analyzer(self, port, uri):
        """Start a TS analyzer for a specific stream"""
        with self.lock:
            if port in self.analyzers:
                self.stop_analyzer(port)
                
            # Create a pipeline specifically for analyzing the TS stream
            pipeline_str = f"""
                uridecodebin uri="{uri}" ! 
                tsdemux name=demux ! fakesink silent=true
            """
            
            try:
                pipeline = Gst.parse_launch(pipeline_str)
                bus = pipeline.get_bus()
                bus.add_signal_watch()
                
                # Store analyzer state
                self.analyzers[port] = {
                    'pipeline': pipeline,
                    'last_pat_time': 0,
                    'last_pmt_time': 0,
                    'last_sdt_time': 0,
                    'pat_interval': 0,
                    'pmt_interval': 0,
                    'sdt_interval': 0,
                    'continuity_errors': 0,
                    'pcr_jitter_ms': 0,
                    'pid_stats': defaultdict(lambda: {'packets': 0, 'last_cc': -1, 'cc_errors': 0}),
                    'program_info': {},
                    'table_repetition_rates': {
                        'PAT': [],  # List of timestamps for calculating average
                        'PMT': [],
                        'SDT': [],
                        'NIT': [],
                    },
                    'start_time': time.time()
                }
                
                # Connect signals to monitor TS tables
                demux = pipeline.get_by_name('demux')
                if demux:
                    # Note: These signals may not be available in all GStreamer versions
                    # We're setting this up to catch them if they exist
                    for signal in ['pat-info', 'pmt-info', 'sdt-info']:
                        try:
                            if hasattr(demux, 'connect') and signal in dir(demux):
                                demux.connect(signal, getattr(self, f'_on_{signal.replace("-", "_")}'), port)
                        except Exception as e:
                            self.logger.warning(f"Could not connect to {signal} signal: {e}")
                
                # Start the pipeline
                pipeline.set_state(Gst.State.PLAYING)
                self.logger.info(f"Started TS analyzer for port {port}")
                return True
                
            except Exception as e:
                self.logger.error(f"Failed to start TS analyzer: {str(e)}")
                return False
    
    def _on_pat_info(self, demux, pat_info, port):
        """Handle PAT table information"""
        with self.lock:
            if port in self.analyzers:
                current_time = time.time()
                analyzer = self.analyzers[port]
                
                # Record PAT timestamp
                analyzer['table_repetition_rates']['PAT'].append(current_time)
                # Keep only last 10 timestamps
                if len(analyzer['table_repetition_rates']['PAT']) > 10:
                    analyzer['table_repetition_rates']['PAT'].pop(0)
                
                # Calculate interval if we have at least 2 timestamps
                if len(analyzer['table_repetition_rates']['PAT']) >= 2:
                    timestamps = analyzer['table_repetition_rates']['PAT']
                    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                    analyzer['pat_interval'] = sum(intervals) / len(intervals) * 1000  # ms
    
    def _on_pmt_info(self, demux, pmt_info, port):
        """Handle PMT table information"""
        with self.lock:
            if port in self.analyzers:
                current_time = time.time()
                analyzer = self.analyzers[port]
                
                # Similar processing as PAT
                analyzer['table_repetition_rates']['PMT'].append(current_time)
                if len(analyzer['table_repetition_rates']['PMT']) > 10:
                    analyzer['table_repetition_rates']['PMT'].pop(0)
                
                if len(analyzer['table_repetition_rates']['PMT']) >= 2:
                    timestamps = analyzer['table_repetition_rates']['PMT']
                    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                    analyzer['pmt_interval'] = sum(intervals) / len(intervals) * 1000  # ms
    
    def _on_sdt_info(self, demux, sdt_info, port):
        """Handle SDT table information"""
        with self.lock:
            if port in self.analyzers:
                current_time = time.time()
                analyzer = self.analyzers[port]
                
                analyzer['table_repetition_rates']['SDT'].append(current_time)
                if len(analyzer['table_repetition_rates']['SDT']) > 10:
                    analyzer['table_repetition_rates']['SDT'].pop(0)
                
                if len(analyzer['table_repetition_rates']['SDT']) >= 2:
                    timestamps = analyzer['table_repetition_rates']['SDT']
                    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                    analyzer['sdt_interval'] = sum(intervals) / len(intervals) * 1000  # ms
    
    def stop_analyzer(self, port):
        """Stop the analyzer for a specific port"""
        with self.lock:
            if port in self.analyzers:
                pipeline = self.analyzers[port]['pipeline']
                pipeline.set_state(Gst.State.NULL)
                del self.analyzers[port]
                self.logger.info(f"Stopped TS analyzer for port {port}")
                return True
            return False
    
    def get_ts_analysis(self, port):
        """Get the analysis results for a specific port"""
        with self.lock:
            if port not in self.analyzers:
                return None
            
            analyzer = self.analyzers[port]
            
            # Prepare results
            analysis = {
                'dvb_compliance': {
                    'pat_interval_ms': analyzer['pat_interval'],
                    'pmt_interval_ms': analyzer['pmt_interval'],
                    'sdt_interval_ms': analyzer['sdt_interval'],
                    'continuity_errors': analyzer['continuity_errors'],
                    'pcr_jitter_ms': analyzer['pcr_jitter_ms'],
                },
                'compliant': True,
                'issues': []
            }
            
            # Check compliance with DVB standards
            if analyzer['pat_interval'] > 500:  # DVB standard: PAT should repeat every 500ms
                analysis['compliant'] = False
                analysis['issues'].append(f"PAT interval too high: {analyzer['pat_interval']:.2f}ms (should be ≤500ms)")
            
            if analyzer['pmt_interval'] > 500:  # PMT should repeat every 500ms
                analysis['compliant'] = False
                analysis['issues'].append(f"PMT interval too high: {analyzer['pmt_interval']:.2f}ms (should be ≤500ms)")
            
            if analyzer['sdt_interval'] > 2000:  # SDT should repeat every 2s
                analysis['compliant'] = False
                analysis['issues'].append(f"SDT interval too high: {analyzer['sdt_interval']:.2f}ms (should be ≤2000ms)")
            
            if analyzer['continuity_errors'] > 0:
                analysis['compliant'] = False
                analysis['issues'].append(f"Continuity counter errors: {analyzer['continuity_errors']}")
            
            if analyzer['pcr_jitter_ms'] > 30:  # PCR jitter should be minimal
                analysis['compliant'] = False
                analysis['issues'].append(f"PCR jitter too high: {analyzer['pcr_jitter_ms']:.2f}ms")
            
            return analysis
