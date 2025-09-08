#!/usr/bin/env python3
"""
Comprehensive Ablation Study Runner with Real MELON and SecurityLingua
Tests the seven-layer pipeline with real SOTA tools
"""

import os
import sys
import json
import time
from typing import List, Dict, Any, Tuple
import pandas as pd
from datetime import datetime

# Import the existing evaluation pipeline
from evaluation_pipeline import AdvancedEvaluationPipeline
from melon import create_melon_adapter
from securitylingua import create_securitylingua_adapter

class ComprehensiveAblationPipeline(AdvancedEvaluationPipeline):
    """Extended pipeline with real MELON and SecurityLingua integration"""
    
    def __init__(self, dataset_path: str = None, disabled_layers: List[str] = None):
        super().__init__(dataset_path)
        self.disabled_layers = disabled_layers or []
        self.melon_adapter = create_melon_adapter()
        self.securitylingua_adapter = create_securitylingua_adapter()
        print(f"�� Ablation mode: Disabled layers = {self.disabled_layers}")
        print(f"🧪 MELON enabled: {self.melon_adapter.enabled}")
        print(f"🛡️ SecurityLingua enabled: {self.securitylingua_adapter.enabled}")
    
    def melon_detection(self, prompt: str):
        """MELON detection using tool"""
        start_time = time.time()
        prediction, confidence = self.melon_adapter.predict(prompt)
        detection_time = time.time() - start_time
        
        return self._create_detection_result(
            prompt=prompt,
            predicted_label=prediction,
            confidence=confidence,
            detection_time=detection_time,
            method="MELON",
            metadata={"tool": "real_melon", "enabled": self.melon_adapter.enabled}
        )
    
    def securitylingua_detection(self, prompt: str):
        """SecurityLingua detection using tool"""
        start_time = time.time()
        prediction, confidence = self.securitylingua_adapter.predict(prompt)
        detection_time = time.time() - start_time
        
        return self._create_detection_result(
            prompt=prompt,
            predicted_label=prediction,
            confidence=confidence,
            detection_time=detection_time,
            method="SecurityLingua",
            metadata={"tool": "real_securitylingua", "enabled": self.securitylingua_adapter.enabled}
        )
    
    def zkp_detection(self, prompt: str):
        """ZKP detection with optional layer disabling"""
        if "zkp" in self.disabled_layers:
            return self._create_neutral_result(prompt, "ZKP Framework")
        return super().zkp_detection(prompt)
    
    def regex_baseline(self, prompt: str):
        """Regex detection with optional layer disabling"""
        if "regex" in self.disabled_layers:
            return self._create_neutral_result(prompt, "Regex Baseline")
        return super().regex_baseline(prompt)
    
    def llm_simulator(self, prompt: str):
        """LLM simulator with optional layer disabling"""
        if "llm" in self.disabled_layers:
            return self._create_neutral_result(prompt, "LLM Simulator")
        return super().llm_simulator(prompt)
    
    def ensemble_detection(self, prompt: str):
        """Ensemble detection with optional layer disabling"""
        if "ensemble" in self.disabled_layers:
            return self._create_neutral_result(prompt, "Ensemble")
        
        # Modify ensemble to exclude disabled layers
        start_time = time.time()
        
        # Get results from enabled methods only
        zkp_result = self.zkp_detection(prompt) if "zkp" not in self.disabled_layers else None
        regex_result = self.regex_baseline(prompt) if "regex" not in self.disabled_layers else None
        llm_result = self.llm_simulator(prompt) if "llm" not in self.disabled_layers else None
        
        # Count enabled methods
        enabled_methods = []
        if zkp_result:
            enabled_methods.append(("ZKP", zkp_result))
        if regex_result:
            enabled_methods.append(("Regex", regex_result))
        if llm_result:
            enabled_methods.append(("LLM", llm_result))
        
        if not enabled_methods:
            return self._create_neutral_result(prompt, "Ensemble")
        
        # Adjust weights based on enabled methods
        total_weight = 0
        ensemble_score = 0
        
        for method_name, result in enabled_methods:
            if method_name == "ZKP":
                weight = 0.2
            elif method_name == "Regex":
                weight = 0.3
            elif method_name == "LLM":
                weight = 0.5
            else:
                weight = 0.33  # Default equal weight
            
            score = 1 if result.predicted_label == "adversarial" else 0
            ensemble_score += score * weight
            total_weight += weight
        
        # Normalize by total weight
        if total_weight > 0:
            ensemble_score /= total_weight
        
        detection_time = time.time() - start_time
        
        return self._create_detection_result(
            prompt=prompt,
            predicted_label="adversarial" if ensemble_score >= 0.15 else "safe",
            confidence=ensemble_score,
            detection_time=detection_time,
            method="Ensemble",
            metadata={
                "enabled_methods": [m[0] for m in enabled_methods],
                "disabled_layers": self.disabled_layers,
                "ensemble_score": ensemble_score
            }
        )
    
    def _create_neutral_result(self, prompt: str, method: str):
        """Create a neutral result when a layer is disabled"""
        return self._create_detection_result(
            prompt=prompt,
            predicted_label="safe",  # Neutral prediction
            confidence=0.5,  # Neutral confidence
            detection_time=0.001,  # Minimal time
            method=method,
            metadata={"layer_disabled": True}
        )
    
    def _create_detection_result(self, prompt: str, predicted_label: str, confidence: float, 
                               detection_time: float, method: str, metadata: Dict[str, Any]):
        """Create a DetectionResult object"""
        from evaluation_pipeline import DetectionResult
        return DetectionResult(
            prompt=prompt,
            true_label="",  # Will be set by caller
            predicted_label=predicted_label,
            confidence=confidence,
            detection_time=detection_time,
            method=method,
            metadata=metadata
        )
    
    def run_comprehensive_evaluation(self):
        """Run comprehensive evaluation with all methods including real tools"""
        print("\n🚀 Starting Comprehensive Ablation Evaluation")
        print("=" * 80)
        
        methods = {
            "ZKP Framework": self.zkp_detection,
            "Regex Baseline": self.regex_baseline,
            "LLM Simulator": self.llm_simulator,
            "Ensemble": self.ensemble_detection,
            "MELON": self.melon_detection,
            "SecurityLingua": self.securitylingua_detection,
        }
        
        all_results = {}
        
        for method_name, method_func in methods.items():
            print(f"\n📊 Evaluating {method_name}...")
            method_results = []
            
            for prompt, true_label in self.test_dataset:
                result = method_func(prompt)
                result.true_label = true_label
                method_results.append(result)
            
            all_results[method_name] = method_results
        
        return all_results

def run_comprehensive_ablation_study(dataset_path: str, output_dir: str):
    """Run comprehensive ablation study with real tools"""
    print(f"\n🔬 Running Comprehensive Ablation Study for {dataset_path}")
    print("=" * 80)
    
    # Define ablation configurations
    ablation_configs = {
        "All_Layers": [],  # No layers disabled (baseline)
        "No_ZKP": ["zkp"],
        "No_Regex": ["regex"], 
        "No_LLM": ["llm"],
        "No_Ensemble": ["ensemble"],
    }
    
    all_results = {}
    
    for config_name, disabled_layers in ablation_configs.items():
        print(f"\n📊 Testing configuration: {config_name}")
        print(f"   Disabled layers: {disabled_layers if disabled_layers else 'None'}")
        
        # Create pipeline with disabled layers
        pipeline = ComprehensiveAblationPipeline(dataset_path, disabled_layers)
        
        # Run evaluation
        results = pipeline.run_comprehensive_evaluation()
        
        # Calculate metrics
        metrics = {}
        for method_name, method_results in results.items():
            metrics[method_name] = pipeline.calculate_metrics(method_results)
        
        all_results[config_name] = {
            'results': results,
            'metrics': metrics,
            'disabled_layers': disabled_layers
        }
        
        # Print summary for this configuration
        print(f"   Results for {config_name}:")
        for method, metric in metrics.items():
            f1 = metric.get('f1', 0.0)
            precision = metric.get('precision', 0.0)
            recall = metric.get('recall', 0.0)
            accuracy = metric.get('accuracy', 0.0)
            latency = metric.get('avg_detection_time', 0.0) * 1000
            
            print(f"     {method}: F1={f1:.3f}, P={precision:.3f}, R={recall:.3f}, A={accuracy:.3f}, L={latency:.1f}ms")
    
    # Save ablation results
    save_comprehensive_ablation_results(all_results, output_dir)
    
    # Print comprehensive ablation analysis
    print_comprehensive_ablation_analysis(all_results)
    
    return all_results

def save_comprehensive_ablation_results(all_results: Dict[str, Any], output_dir: str):
    """Save comprehensive ablation results to CSV files"""
    os.makedirs(output_dir, exist_ok=True)
    
    # Save metrics summary
    metrics_data = []
    for config_name, config_data in all_results.items():
        for method_name, metrics in config_data['metrics'].items():
            row = {
                'configuration': config_name,
                'method': method_name,
                'disabled_layers': ','.join(config_data['disabled_layers']),
                **metrics
            }
            metrics_data.append(row)
    
    metrics_df = pd.DataFrame(metrics_data)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    metrics_file = os.path.join(output_dir, f'comprehensive_ablation_metrics_{timestamp}.csv')
    metrics_df.to_csv(metrics_file, index=False)
    print(f"✅ Saved comprehensive ablation metrics to {metrics_file}")
    
    # Save detailed results for each configuration
    for config_name, config_data in all_results.items():
        detailed_data = []
        for method_name, results in config_data['results'].items():
            for result in results:
                detailed_data.append({
                    'configuration': config_name,
                    'method': method_name,
                    'prompt': result.prompt,
                    'true_label': result.true_label,
                    'predicted_label': result.predicted_label,
                    'confidence': result.confidence,
                    'detection_time': result.detection_time,
                    'metadata': json.dumps(result.metadata)
                })
        
        detailed_df = pd.DataFrame(detailed_data)
        detailed_file = os.path.join(output_dir, f'comprehensive_ablation_detailed_{config_name}_{timestamp}.csv')
        detailed_df.to_csv(detailed_file, index=False)

def print_comprehensive_ablation_analysis(all_results: Dict[str, Any]):
    """Print comprehensive ablation analysis with real tools"""
    print("\n" + "=" * 80)
    print("🔍 COMPREHENSIVE ABLATION ANALYSIS WITH REAL TOOLS")
    print("=" * 80)
    
    # Get baseline (All_Layers) metrics
    baseline_metrics = all_results.get("All_Layers", {}).get("metrics", {})
    
    print(f"\n📊 Layer Contribution Analysis:")
    print(f"{'Configuration':<20} {'Method':<15} {'F1':<8} {'Precision':<10} {'Recall':<8} {'Accuracy':<9} {'Latency(ms)':<12}")
    print("-" * 100)
    
    for config_name, config_data in all_results.items():
        for method_name, metrics in config_data['metrics'].items():
            f1 = metrics.get('f1', 0.0)
            precision = metrics.get('precision', 0.0)
            recall = metrics.get('recall', 0.0)
            accuracy = metrics.get('accuracy', 0.0)
            latency = metrics.get('avg_detection_time', 0.0) * 1000
            
            print(f"{config_name:<20} {method_name:<15} {f1:<8.3f} {precision:<10.3f} {recall:<8.3f} {accuracy:<9.3f} {latency:<12.1f}")
    
    # Calculate performance drops
    print(f"\n📉 Performance Impact Analysis (vs Baseline):")
    print(f"{'Configuration':<20} {'Method':<15} {'F1 Drop':<10} {'Precision Drop':<15} {'Recall Drop':<12} {'Accuracy Drop':<15}")
    print("-" * 100)
    
    for config_name, config_data in all_results.items():
        if config_name == "All_Layers":
            continue
            
        for method_name, metrics in config_data['metrics'].items():
            if method_name in baseline_metrics:
                baseline = baseline_metrics[method_name]
                
                f1_drop = baseline.get('f1', 0) - metrics.get('f1', 0)
                precision_drop = baseline.get('precision', 0) - metrics.get('precision', 0)
                recall_drop = baseline.get('recall', 0) - metrics.get('recall', 0)
                accuracy_drop = baseline.get('accuracy', 0) - metrics.get('accuracy', 0)
                
                print(f"{config_name:<20} {method_name:<15} {f1_drop:<10.3f} {precision_drop:<15.3f} {recall_drop:<12.3f} {accuracy_drop:<15.3f}")
    
    # Real tools comparison
    print(f"\n🏆 Tools vs Pipeline Methods Comparison:")
    print(f"{'Method':<15} {'F1':<8} {'Precision':<10} {'Recall':<8} {'Accuracy':<9} {'Latency(ms)':<12} {'Tool Type':<15}")
    print("-" * 100)
    
    baseline_methods = baseline_metrics.keys()
    for method_name in baseline_methods:
        metrics = baseline_metrics[method_name]
        f1 = metrics.get('f1', 0.0)
        precision = metrics.get('precision', 0.0)
        recall = metrics.get('recall', 0.0)
        accuracy = metrics.get('accuracy', 0.0)
        latency = metrics.get('avg_detection_time', 0.0) * 1000
        
        tool_type = "Real Tool" if method_name in ["MELON", "SecurityLingua"] else "Pipeline Method"
        
        print(f"{method_name:<15} {f1:<8.3f} {precision:<10.3f} {recall:<8.3f} {accuracy:<9.3f} {latency:<12.1f} {tool_type:<15}")

def main():
    """Main function to run comprehensive ablation studies"""
    datasets = ['data/6kdata.json', 'data/120kdata.json']
    
    for dataset_path in datasets:
        if not os.path.exists(dataset_path):
            print(f"⚠️ Dataset not found: {dataset_path}")
            continue
        
        dataset_name = os.path.splitext(os.path.basename(dataset_path))[0]
        output_dir = os.path.join('results', f'{dataset_name}_comprehensive_ablation')
        
        try:
            results = run_comprehensive_ablation_study(dataset_path, output_dir)
            print(f"\n✅ Comprehensive ablation study completed for {dataset_path}")
        except Exception as e:
            print(f"❌ Error running comprehensive ablation study for {dataset_path}: {e}")
    
    print(f"\n🎉 All comprehensive ablation studies completed!")

if __name__ == '__main__':
    main()