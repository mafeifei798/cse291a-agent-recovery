from agent_l_batch.launch import launch as prior_launch


def launch(*args, **kwargs):
    return prior_launch(*args, profile='feedback-v3', **kwargs)
