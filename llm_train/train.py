import os
import torch
from torch.nn import functional as F
from tqdm import tqdm
from transformers import AutoTokenizer, AdamW, AutoModelForCausalLM
import matplotlib.pyplot as plt

from data_loader import DataLoader
from model_adjust import ModelAdjuster, ModelConfig, ActivityType, fetch_adjusted_model

max_token_length = 4096
batch_size = 1
step_accumulation = 8
epoch_count = 1
model_save_interval = 400
log_interval = 50
learning_rate = 0.0001
model_directory = "..."
data_file = "..."
training_type = "sft"
use_adjustment = True
previous_adjust_path = ""
adjust_rank = 8
adjust_scale = 32

stats_tracking = {
    "steps": [],
    "losses": []
}
current_step = 0

def plot_loss():
    steps = stats_tracking["steps"]
    losses = stats_tracking["losses"]

    plt.plot(steps, losses, 'o-', color='blue', label="loss")
    plt.xlabel("Steps")
    plt.ylabel("Loss")
    plt.savefig('loss_plot.png')

def setup_data():
    if training_type == "pretrain":
        data_obj = DataLoader(
            tokenizer, batch_size, max_token_length,
            data_path=data_file)
    else:
        data_obj = DataLoader(tokenizer, batch_size, max_token_length,
                              data_path=data_file)
    return data_obj

def setup_model():
    model_config = transformers.AutoConfig.from_pretrained(
        model_directory,
        trust_remote_code=True,
    )
    model_config.use_cache = False
    model = AutoModelForCausalLM.from_pretrained(model_directory, trust_remote_code=True, device_map="auto")
    if use_adjustment:
        if previous_adjust_path:
            model = ModelAdjuster.from_pretrained(model, previous_adjust_path, is_trainable=True)
        else:
            trainable_layers = identify_trainable_layers(model)
            adjust_config = ModelConfig(
                activity_type=ActivityType.CAUSAL_LM,
                inference_mode=False,
                dimension=adjust_rank,
                scale=adjust_scale,
                dropout=0.1,
                targets=trainable_layers
            )
            model = fetch_adjusted_model(model, adjust_config)
    model.supports_gradient_checkpointing = True
    model.gradient_checkpointing_enable()
    model.enable_input_require_grads()
    return model

def identify_trainable_layers(model_adjust):
    cls = torch.nn.Linear
    layer_names = set()
    for name, module in model_adjust.named_modules():
        if isinstance(module, cls) and 'lm_head' not in name:
            layer_part = name.split('.')
            layer_names.add(layer_part[0] if len(layer_part) == 1 else layer_part[-1])
    return sorted(layer_names)

def save_model(model, path):
    model.save_pretrained(path)

def show_model_info(model):
    total_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f'Total trainable parameters: {total_params / 1000000}M total:{total_params}')

def run_training(model, epoch):
    global stats_tracking, current_step
    data_obj = setup_data()
    model.train()
    model_params = filter(lambda p: p.requires_grad, model.parameters())
    total_length = len(data_obj)
    progress = tqdm(range(total_length))
    running_loss = 0
    total_loss = 0
    for data in data_obj.get_data():
        input_ids = data["input_ids"].cuda()
        labels = data["labels"].cuda()
        loss = model(input_ids=input_ids, labels=labels)[0]
        displayed_loss = loss.item()
        running_loss += displayed_loss
        total_loss += displayed_loss
        loss = loss / step_accumulation
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model_params, 1.0)
        if current_step % step_accumulation == 0:
            optimizer.step()
            optimizer.zero_grad()
        if current_step % log_interval == 0:
            print(f"Step: {current_step}, Loss: {running_loss / log_interval}")
            stats_tracking["steps"].append(current_step)
            stats_tracking["losses"].append(running_loss / log_interval)
            running_loss = 0
            plot_loss()
        if current_step % model_save_interval == 0:
            save_model(model, f"{output_dir}/epoch-{epoch}-step-{current_step}")
        progress.set_postfix({
            "Step": current_step,
            "Loss": displayed_loss
        })
        progress.update(1)
        current_step += 1
    print(f"Epoch:{epoch} Loss:{total_loss / total_length}")
    stats_tracking["steps"].append(current_step)
    stats_tracking["losses"].append(total_loss / total_length)
    plot_loss()
    progress.close()
    save_model(model, f"{output_dir}/secgpt-base-epoch-{i + 1}")

if __name__ == "__main__":
    output_dir = "./output"
    tokenizer = AutoTokenizer.from_pretrained(model_directory, trust_remote_code=True)
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)
    data_obj = setup_data()
    model_obj = setup_model()
    show_model_info(model_obj)

    optimizer = AdamW(model_obj.parameters(), lr=learning_rate, correct_bias=True)

    for i in range(epoch_count):
        run_training(model_obj, i)
