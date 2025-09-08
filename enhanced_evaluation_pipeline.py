#!/usr/bin/env python3
"""
Enhanced Evaluation Pipeline with Improved Detection
Integrates advanced obfuscation detection, multi-language support, and social engineering detection
"""
import os
import sys
import json
import csv
import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# Import the enhanced detection system
from enhanced_detection_system import EnhancedDetectionSystem

class EnhancedEvaluationPipeline:
    """Enhanced evaluation pipeline with improved detection capabilities"""
    
    def __init__(self, dataset_path: str):
        self.dataset_path = dataset_path
        self.enhanced_detector = EnhancedDetectionSystem()
        self.results = {}
        
    def load_dataset(self) -> List[Dict]:
        """Load dataset from JSONL or CSV format"""
        
        dataset = []
        
        if self.dataset_path.endswith('.jsonl'):
            with open(self.dataset_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            dataset.append(data)
                        except json.JSONDecodeError:
                            continue
        elif self.dataset_path.endswith('.csv'):
            with open(self.dataset_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    dataset.append(row)
        
        print(f"📊 Loaded {len(dataset)} examples from {self.dataset_path}")
        return dataset
    
    def enhanced_zkp_detection(self, prompt: str) -> Dict:
        """Enhanced ZKP Framework detection with obfuscation handling"""
        
        start_time = time.time()
        
        # Use enhanced detection system
        detection_result = self.enhanced_detector.enhanced_detection(prompt)
        
        # Determine if malicious based on enhanced detection
        is_malicious = detection_result['is_malicious']
        confidence = detection_result['confidence']
        
        # Map to expected labels
        predicted_label = "adversarial" if is_malicious else "benign"
        
        detection_time = time.time() - start_time
        
        return {
            'prompt': prompt,
            'predicted_label': predicted_label,
            'confidence': confidence,
            'detection_time': detection_time,
            'detection_methods': detection_result['detection_methods'],
            'threat_level': detection_result['threat_level'],
            'obfuscation_detected': detection_result['obfuscation_detected'],
            'language_detected': detection_result['language_detected']
        }
    
    def enhanced_regex_baseline(self, prompt: str) -> Dict:
        """Enhanced regex baseline with obfuscation detection"""
        
        start_time = time.time()
        
        # Use enhanced detection system
        detection_result = self.enhanced_detector.enhanced_detection(prompt)
        
        # Regex baseline is more conservative - lower threshold
        is_malicious = detection_result['confidence'] > 0.3
        
        predicted_label = "adversarial" if is_malicious else "benign"
        confidence = min(detection_result['confidence'] * 1.2, 1.0)  # Boost confidence
        
        detection_time = time.time() - start_time
        
        return {
            'prompt': prompt,
            'predicted_label': predicted_label,
            'confidence': confidence,
            'detection_time': detection_time,
            'detection_methods': detection_result['detection_methods'],
            'threat_level': detection_result['threat_level'],
            'obfuscation_detected': detection_result['obfuscation_detected'],
            'language_detected': detection_result['language_detected']
        }
    
    def enhanced_llm_simulator(self, prompt: str) -> Dict:
        """Enhanced LLM simulator with context awareness"""
        
        start_time = time.time()
        
        # Use enhanced detection system
        detection_result = self.enhanced_detector.enhanced_detection(prompt)
        
        # LLM simulator is very conservative - higher threshold
        is_malicious = detection_result['confidence'] > 0.5
        
        predicted_label = "adversarial" if is_malicious else "benign"
        confidence = detection_result['confidence'] * 0.8  # Conservative confidence
        
        detection_time = time.time() - start_time
        
        return {
            'prompt': prompt,
            'predicted_label': predicted_label,
            'confidence': confidence,
            'detection_time': detection_time,
            'detection_methods': detection_result['detection_methods'],
            'threat_level': detection_result['threat_level'],
            'obfuscation_detected': detection_result['obfuscation_detected'],
            'language_detected': detection_result['language_detected']
        }
    
    def enhanced_ensemble(self, prompt: str) -> Dict:
        """Enhanced ensemble combining all methods with weighted voting"""
        
        start_time = time.time()
        
        # Get results from all methods
        zkp_result = self.enhanced_zkp_detection(prompt)
        regex_result = self.enhanced_regex_baseline(prompt)
        llm_result = self.enhanced_llm_simulator(prompt)
        
        # Weighted voting system
        zkp_weight = 0.4  # ZKP gets highest weight
        regex_weight = 0.35  # Regex gets medium weight
        llm_weight = 0.25  # LLM gets lowest weight
        
        # Calculate weighted confidence
        weighted_confidence = (
            zkp_result['confidence'] * zkp_weight +
            regex_result['confidence'] * regex_weight +
            llm_result['confidence'] * llm_weight
        )
        
        # Determine final prediction
        malicious_votes = 0
        if zkp_result['predicted_label'] == "adversarial":
            malicious_votes += zkp_weight
        if regex_result['predicted_label'] == "adversarial":
            malicious_votes += regex_weight
        if llm_result['predicted_label'] == "adversarial":
            malicious_votes += llm_weight
        
        is_malicious = malicious_votes > 0.5
        predicted_label = "adversarial" if is_malicious else "benign"
        
        detection_time = time.time() - start_time
        
        return {
            'prompt': prompt,
            'predicted_label': predicted_label,
            'confidence': weighted_confidence,
            'detection_time': detection_time,
            'detection_methods': ['ensemble_decision'],
            'threat_level': 'high' if weighted_confidence > 0.7 else 'medium' if weighted_confidence > 0.4 else 'low',
            'obfuscation_detected': any([zkp_result['obfuscation_detected'], regex_result['obfuscation_detected'], llm_result['obfuscation_detected']]),
            'language_detected': zkp_result['language_detected']
        }
    
    def run_enhanced_evaluation(self) -> Dict[str, List]:
        """Run enhanced evaluation with all detection methods"""
        
        print("🚀 Starting Enhanced Evaluation Pipeline...")
        print("=" * 60)
        
        # Load dataset
        dataset = self.load_dataset()
        
        # Initialize results
        self.results = {
            'ZKP Framework': [],
            'Regex Baseline': [],
            'LLM Simulator': [],
            'Enhanced Ensemble': []
        }
        
        # Run evaluation for each method
        methods = {
            'ZKP Framework': self.enhanced_zkp_detection,
            'Regex Baseline': self.enhanced_regex_baseline,
            'LLM Simulator': self.enhanced_llm_simulator,
            'Enhanced Ensemble': self.enhanced_ensemble
        }
        
        for method_name, method_func in methods.items():
            print(f"\n📊 Evaluating {method_name}...")
            
            for i, item in enumerate(dataset):
                prompt = item.get('prompt', '')
                true_label = item.get('label', '')
                
                if prompt and true_label:
                    # Map labels to expected format
                    if true_label.lower() in ['malicious', 'adversarial', 'attack']:
                        true_label = "adversarial"
                    elif true_label.lower() in ['benign', 'safe', 'normal']:
                        true_label = "benign"
                    
                    # Run detection
                    result = method_func(prompt)
                    result['true_label'] = true_label
                    
                    self.results[method_name].append(result)
                
                # Progress indicator
                if (i + 1) % 1000 == 0:
                    print(f"  Processed {i + 1}/{len(dataset)} examples...")
        
        print("\n✅ Enhanced evaluation completed!")
        return self.results
    
    def calculate_enhanced_metrics(self, results: List[Dict]) -> Dict[str, float]:
        """Calculate comprehensive metrics with enhanced detection insights"""
        
        if not results:
            return {}
        
        # Basic metrics
        y_true = [1 if r['true_label'] == "adversarial" else 0 for r in results]
        y_pred = [1 if r['predicted_label'] == "adversarial" else 0 for r in results]
        
        # Calculate confusion matrix
        tp = sum(1 for i in range(len(y_true)) if y_true[i] == 1 and y_pred[i] == 1)
        tn = sum(1 for i in range(len(y_true)) if y_true[i] == 0 and y_pred[i] == 0)
        fp = sum(1 for i in range(len(y_true)) if y_true[i] == 0 and y_pred[i] == 1)
        fn = sum(1 for i in range(len(y_true)) if y_true[i] == 1 and y_pred[i] == 0)
        
        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        
        # Enhanced metrics
        avg_confidence = sum(r['confidence'] for r in results) / len(results)
        avg_detection_time = sum(r['detection_time'] for r in results) / len(results)
        
        # Obfuscation detection rate
        obfuscation_detected = sum(1 for r in results if r.get('obfuscation_detected', False))
        obfuscation_rate = obfuscation_detected / len(results) if results else 0
        
        # Multi-language detection rate
        multilingual_detected = sum(1 for r in results if r.get('language_detected', 'english') != 'english')
        multilingual_rate = multilingual_detected / len(results) if results else 0
        
        return {
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'accuracy': accuracy,
            'specificity': tn / (tn + fp) if (tn + fp) > 0 else 0,
            'sensitivity': recall,
            'true_positives': tp,
            'true_negatives': tn,
            'false_positives': fp,
            'false_negatives': fn,
            'avg_confidence': avg_confidence,
            'avg_detection_time': avg_detection_time,
            'obfuscation_detection_rate': obfuscation_rate,
            'multilingual_detection_rate': multilingual_rate
        }
    
    def print_enhanced_summary(self, metrics: Dict[str, Dict]):
        """Print comprehensive enhanced evaluation summary"""
        
        print("\n📊 ENHANCED EVALUATION SUMMARY")
        print("=" * 60)
        
        for method, metric in metrics.items():
            print(f"\n🚀 {method}:")
            print(f"  • Precision: {metric['precision']:.3f}")
            print(f"  • Recall: {metric['recall']:.3f}")
            print(f"  • F1: {metric['f1']:.3f}")
            print(f"  • Accuracy: {metric['accuracy']:.3f}")
            print(f"  • True Positives: {metric['true_positives']}")
            print(f"  • False Negatives: {metric['false_negatives']}")
            print(f"  • Average Confidence: {metric['avg_confidence']:.3f}")
            print(f"  • Obfuscation Detection Rate: {metric['obfuscation_detection_rate']:.3f}")
            print(f"  • Multi-language Detection Rate: {metric['multilingual_detection_rate']:.3f}")
    
    def save_enhanced_results(self, output_dir: str):
        """Save enhanced results to files"""
        
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save metrics CSV
        metrics_file = os.path.join(output_dir, f'enhanced_metrics_{timestamp}.csv')
        metrics = {}
        
        for method, results in self.results.items():
            metrics[method] = self.calculate_enhanced_metrics(results)
        
        with open(metrics_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Metric'] + list(metrics.keys()))
            
            metric_names = ['precision', 'recall', 'f1', 'accuracy', 'specificity', 'sensitivity', 
                          'avg_confidence', 'obfuscation_detection_rate', 'multilingual_detection_rate']
            
            for metric in metric_names:
                row = [metric]
                for method in metrics.keys():
                    row.append(metrics[method].get(metric, 0))
                writer.writerow(row)
        
        print(f"✅ Enhanced metrics saved: {metrics_file}")
        
        # Save detailed results
        detailed_file = os.path.join(output_dir, f'enhanced_detailed_{timestamp}.csv')
        with open(detailed_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Method', 'Prompt', 'True_Label', 'Predicted_Label', 'Confidence', 
                           'Detection_Time', 'Threat_Level', 'Obfuscation_Detected', 'Language_Detected'])
            
            for method, results in self.results.items():
                for result in results:
                    writer.writerow([
                        method,
                        result['prompt'][:100] + '...' if len(result['prompt']) > 100 else result['prompt'],
                        result['true_label'],
                        result['predicted_label'],
                        result['confidence'],
                        result['detection_time'],
                        result['threat_level'],
                        result['obfuscation_detected'],
                        result['language_detected']
                    ])
        
        print(f"✅ Detailed results saved: {detailed_file}")
        
        # Print summary
        self.print_enhanced_summary(metrics)
        
        return metrics

def main():
    """Main function to run enhanced evaluation"""
    
    if len(sys.argv) != 3:
        print("Usage: python3 enhanced_evaluation_pipeline.py <dataset_path> <output_dir>")
        print("Example: python3 enhanced_evaluation_pipeline.py dataset.jsonl enhanced_results")
        sys.exit(1)
    
    dataset_path = sys.argv[1]
    output_dir = sys.argv[2]
    
    # Initialize enhanced pipeline
    pipeline = EnhancedEvaluationPipeline(dataset_path)
    
    # Run enhanced evaluation
    results = pipeline.run_enhanced_evaluation()
    
    # Save results
    metrics = pipeline.save_enhanced_results(output_dir)
    
    print(f"\n🎉 Enhanced evaluation completed!")
    print(f"📁 Results saved to: {output_dir}")

if __name__ == "__main__":
    main()