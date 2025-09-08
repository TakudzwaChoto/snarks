#!/usr/bin/env python3
"""
Simplified CSV Evaluation Runner
Runs evaluation and outputs results to CSV without matplotlib dependencies
"""

import os
import sys
import json
import csv
from datetime import datetime

# Import the evaluation pipeline
try:
    from evaluation_pipeline import AdvancedEvaluationPipeline
except ImportError:
    print("❌ Could not import AdvancedEvaluationPipeline. Make sure evaluation_pipeline.py is available.")
    sys.exit(1)

def main():
    # Parse arguments
    if len(sys.argv) != 3:
        print("Usage: python3 run_csv_evaluation.py <dataset_path> <output_dir>")
        print("Example: python3 run_csv_evaluation.py data/4kdata.csv results_csv")
        sys.exit(1)
    
    dataset_path = sys.argv[1]
    output_dir = sys.argv[2]
    
    # Setup output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Run evaluation
    print("🚀 Running CSV evaluation...")
    
    try:
        pipeline = AdvancedEvaluationPipeline(dataset_path)
        all_results = pipeline.run_evaluation()
        
        if not all_results:
            print("❌ No results returned from evaluation!")
            sys.exit(1)
        
        # Compute metrics per method
        metrics = {}
        for method, results in all_results.items():
            metrics[method] = pipeline.calculate_metrics(results)
        
        # Save detailed results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save metrics CSV
        metrics_file = os.path.join(output_dir, f'metrics_{timestamp}.csv')
        with open(metrics_file, 'w', newline='') as f:
            writer = csv.writer(f)
            # Write header
            methods = list(metrics.keys())
            writer.writerow(['Metric'] + methods)
            
            # Write each metric
            metric_names = ['precision', 'recall', 'f1', 'accuracy', 'specificity', 'sensitivity', 'avg_detection_time']
            for metric in metric_names:
                row = [metric]
                for method in methods:
                    row.append(metrics[method].get(metric, 0))
                writer.writerow(row)
            
            # Write confusion matrix data
            writer.writerow([])  # Empty row
            writer.writerow(['Confusion Matrix Data'])
            writer.writerow(['Method', 'True Positives', 'True Negatives', 'False Positives', 'False Negatives'])
            for method in methods:
                cm_data = metrics[method]
                writer.writerow([
                    method,
                    cm_data.get('true_positives', 0),
                    cm_data.get('true_negatives', 0),
                    cm_data.get('false_positives', 0),
                    cm_data.get('false_negatives', 0)
                ])
        
        print(f"✅ Metrics saved to {metrics_file}")
        
        # Save detailed results per method
        detailed_file = os.path.join(output_dir, f'detailed_results_{timestamp}.csv')
        with open(detailed_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Method', 'Prompt', 'True Label', 'Predicted Label', 'Confidence', 'Detection Time (ms)'])
            
            for method, results in all_results.items():
                for result in results:
                    writer.writerow([
                        method,
                        result.prompt[:100] + '...' if len(result.prompt) > 100 else result.prompt,
                        result.true_label,
                        result.predicted_label,
                        f"{result.confidence:.3f}",
                        f"{result.detection_time * 1000:.3f}"
                    ])
        
        print(f"✅ Detailed results saved to {detailed_file}")
        
        # Print summary
        print(f"\n📊 EVALUATION SUMMARY")
        print("=" * 60)
        for method, metric in metrics.items():
            print(f"\n{method}:")
            print(f"  • Precision: {metric['precision']:.3f}")
            print(f"  • Recall: {metric['recall']:.3f}")
            print(f"  • F1: {metric['f1']:.3f}")
            print(f"  • Accuracy: {metric['accuracy']:.3f}")
            print(f"  • True Positives: {metric['true_positives']}")
            print(f"  • False Negatives: {metric['false_negatives']}")
        
        print(f"\n✅ Done! Results saved to {output_dir}")
        
    except Exception as e:
        print(f"❌ Evaluation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()