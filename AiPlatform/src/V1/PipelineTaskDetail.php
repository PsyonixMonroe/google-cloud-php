<?php
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: google/cloud/aiplatform/v1/pipeline_job.proto

namespace Google\Cloud\AIPlatform\V1;

use Google\Protobuf\Internal\GPBType;
use Google\Protobuf\Internal\RepeatedField;
use Google\Protobuf\Internal\GPBUtil;

/**
 * The runtime detail of a task execution.
 *
 * Generated from protobuf message <code>google.cloud.aiplatform.v1.PipelineTaskDetail</code>
 */
class PipelineTaskDetail extends \Google\Protobuf\Internal\Message
{
    /**
     * Output only. The system generated ID of the task.
     *
     * Generated from protobuf field <code>int64 task_id = 1 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     */
    private $task_id = 0;
    /**
     * Output only. The id of the parent task if the task is within a component scope.
     * Empty if the task is at the root level.
     *
     * Generated from protobuf field <code>int64 parent_task_id = 12 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     */
    private $parent_task_id = 0;
    /**
     * Output only. The user specified name of the task that is defined in
     * [PipelineJob.spec][].
     *
     * Generated from protobuf field <code>string task_name = 2 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     */
    private $task_name = '';
    /**
     * Output only. Task create time.
     *
     * Generated from protobuf field <code>.google.protobuf.Timestamp create_time = 3 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     */
    private $create_time = null;
    /**
     * Output only. Task start time.
     *
     * Generated from protobuf field <code>.google.protobuf.Timestamp start_time = 4 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     */
    private $start_time = null;
    /**
     * Output only. Task end time.
     *
     * Generated from protobuf field <code>.google.protobuf.Timestamp end_time = 5 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     */
    private $end_time = null;
    /**
     * Output only. The detailed execution info.
     *
     * Generated from protobuf field <code>.google.cloud.aiplatform.v1.PipelineTaskExecutorDetail executor_detail = 6 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     */
    private $executor_detail = null;
    /**
     * Output only. State of the task.
     *
     * Generated from protobuf field <code>.google.cloud.aiplatform.v1.PipelineTaskDetail.State state = 7 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     */
    private $state = 0;
    /**
     * Output only. The execution metadata of the task.
     *
     * Generated from protobuf field <code>.google.cloud.aiplatform.v1.Execution execution = 8 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     */
    private $execution = null;
    /**
     * Output only. The error that occurred during task execution.
     * Only populated when the task's state is FAILED or CANCELLED.
     *
     * Generated from protobuf field <code>.google.rpc.Status error = 9 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     */
    private $error = null;
    /**
     * Output only. A list of task status. This field keeps a record of task status evolving
     * over time.
     *
     * Generated from protobuf field <code>repeated .google.cloud.aiplatform.v1.PipelineTaskDetail.PipelineTaskStatus pipeline_task_status = 13 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     */
    private $pipeline_task_status;
    /**
     * Output only. The runtime input artifacts of the task.
     *
     * Generated from protobuf field <code>map<string, .google.cloud.aiplatform.v1.PipelineTaskDetail.ArtifactList> inputs = 10 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     */
    private $inputs;
    /**
     * Output only. The runtime output artifacts of the task.
     *
     * Generated from protobuf field <code>map<string, .google.cloud.aiplatform.v1.PipelineTaskDetail.ArtifactList> outputs = 11 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     */
    private $outputs;

    /**
     * Constructor.
     *
     * @param array $data {
     *     Optional. Data for populating the Message object.
     *
     *     @type int|string $task_id
     *           Output only. The system generated ID of the task.
     *     @type int|string $parent_task_id
     *           Output only. The id of the parent task if the task is within a component scope.
     *           Empty if the task is at the root level.
     *     @type string $task_name
     *           Output only. The user specified name of the task that is defined in
     *           [PipelineJob.spec][].
     *     @type \Google\Protobuf\Timestamp $create_time
     *           Output only. Task create time.
     *     @type \Google\Protobuf\Timestamp $start_time
     *           Output only. Task start time.
     *     @type \Google\Protobuf\Timestamp $end_time
     *           Output only. Task end time.
     *     @type \Google\Cloud\AIPlatform\V1\PipelineTaskExecutorDetail $executor_detail
     *           Output only. The detailed execution info.
     *     @type int $state
     *           Output only. State of the task.
     *     @type \Google\Cloud\AIPlatform\V1\Execution $execution
     *           Output only. The execution metadata of the task.
     *     @type \Google\Rpc\Status $error
     *           Output only. The error that occurred during task execution.
     *           Only populated when the task's state is FAILED or CANCELLED.
     *     @type \Google\Cloud\AIPlatform\V1\PipelineTaskDetail\PipelineTaskStatus[]|\Google\Protobuf\Internal\RepeatedField $pipeline_task_status
     *           Output only. A list of task status. This field keeps a record of task status evolving
     *           over time.
     *     @type array|\Google\Protobuf\Internal\MapField $inputs
     *           Output only. The runtime input artifacts of the task.
     *     @type array|\Google\Protobuf\Internal\MapField $outputs
     *           Output only. The runtime output artifacts of the task.
     * }
     */
    public function __construct($data = NULL) {
        \GPBMetadata\Google\Cloud\Aiplatform\V1\PipelineJob::initOnce();
        parent::__construct($data);
    }

    /**
     * Output only. The system generated ID of the task.
     *
     * Generated from protobuf field <code>int64 task_id = 1 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @return int|string
     */
    public function getTaskId()
    {
        return $this->task_id;
    }

    /**
     * Output only. The system generated ID of the task.
     *
     * Generated from protobuf field <code>int64 task_id = 1 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @param int|string $var
     * @return $this
     */
    public function setTaskId($var)
    {
        GPBUtil::checkInt64($var);
        $this->task_id = $var;

        return $this;
    }

    /**
     * Output only. The id of the parent task if the task is within a component scope.
     * Empty if the task is at the root level.
     *
     * Generated from protobuf field <code>int64 parent_task_id = 12 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @return int|string
     */
    public function getParentTaskId()
    {
        return $this->parent_task_id;
    }

    /**
     * Output only. The id of the parent task if the task is within a component scope.
     * Empty if the task is at the root level.
     *
     * Generated from protobuf field <code>int64 parent_task_id = 12 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @param int|string $var
     * @return $this
     */
    public function setParentTaskId($var)
    {
        GPBUtil::checkInt64($var);
        $this->parent_task_id = $var;

        return $this;
    }

    /**
     * Output only. The user specified name of the task that is defined in
     * [PipelineJob.spec][].
     *
     * Generated from protobuf field <code>string task_name = 2 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @return string
     */
    public function getTaskName()
    {
        return $this->task_name;
    }

    /**
     * Output only. The user specified name of the task that is defined in
     * [PipelineJob.spec][].
     *
     * Generated from protobuf field <code>string task_name = 2 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @param string $var
     * @return $this
     */
    public function setTaskName($var)
    {
        GPBUtil::checkString($var, True);
        $this->task_name = $var;

        return $this;
    }

    /**
     * Output only. Task create time.
     *
     * Generated from protobuf field <code>.google.protobuf.Timestamp create_time = 3 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @return \Google\Protobuf\Timestamp|null
     */
    public function getCreateTime()
    {
        return $this->create_time;
    }

    public function hasCreateTime()
    {
        return isset($this->create_time);
    }

    public function clearCreateTime()
    {
        unset($this->create_time);
    }

    /**
     * Output only. Task create time.
     *
     * Generated from protobuf field <code>.google.protobuf.Timestamp create_time = 3 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @param \Google\Protobuf\Timestamp $var
     * @return $this
     */
    public function setCreateTime($var)
    {
        GPBUtil::checkMessage($var, \Google\Protobuf\Timestamp::class);
        $this->create_time = $var;

        return $this;
    }

    /**
     * Output only. Task start time.
     *
     * Generated from protobuf field <code>.google.protobuf.Timestamp start_time = 4 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @return \Google\Protobuf\Timestamp|null
     */
    public function getStartTime()
    {
        return $this->start_time;
    }

    public function hasStartTime()
    {
        return isset($this->start_time);
    }

    public function clearStartTime()
    {
        unset($this->start_time);
    }

    /**
     * Output only. Task start time.
     *
     * Generated from protobuf field <code>.google.protobuf.Timestamp start_time = 4 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @param \Google\Protobuf\Timestamp $var
     * @return $this
     */
    public function setStartTime($var)
    {
        GPBUtil::checkMessage($var, \Google\Protobuf\Timestamp::class);
        $this->start_time = $var;

        return $this;
    }

    /**
     * Output only. Task end time.
     *
     * Generated from protobuf field <code>.google.protobuf.Timestamp end_time = 5 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @return \Google\Protobuf\Timestamp|null
     */
    public function getEndTime()
    {
        return $this->end_time;
    }

    public function hasEndTime()
    {
        return isset($this->end_time);
    }

    public function clearEndTime()
    {
        unset($this->end_time);
    }

    /**
     * Output only. Task end time.
     *
     * Generated from protobuf field <code>.google.protobuf.Timestamp end_time = 5 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @param \Google\Protobuf\Timestamp $var
     * @return $this
     */
    public function setEndTime($var)
    {
        GPBUtil::checkMessage($var, \Google\Protobuf\Timestamp::class);
        $this->end_time = $var;

        return $this;
    }

    /**
     * Output only. The detailed execution info.
     *
     * Generated from protobuf field <code>.google.cloud.aiplatform.v1.PipelineTaskExecutorDetail executor_detail = 6 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @return \Google\Cloud\AIPlatform\V1\PipelineTaskExecutorDetail|null
     */
    public function getExecutorDetail()
    {
        return $this->executor_detail;
    }

    public function hasExecutorDetail()
    {
        return isset($this->executor_detail);
    }

    public function clearExecutorDetail()
    {
        unset($this->executor_detail);
    }

    /**
     * Output only. The detailed execution info.
     *
     * Generated from protobuf field <code>.google.cloud.aiplatform.v1.PipelineTaskExecutorDetail executor_detail = 6 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @param \Google\Cloud\AIPlatform\V1\PipelineTaskExecutorDetail $var
     * @return $this
     */
    public function setExecutorDetail($var)
    {
        GPBUtil::checkMessage($var, \Google\Cloud\AIPlatform\V1\PipelineTaskExecutorDetail::class);
        $this->executor_detail = $var;

        return $this;
    }

    /**
     * Output only. State of the task.
     *
     * Generated from protobuf field <code>.google.cloud.aiplatform.v1.PipelineTaskDetail.State state = 7 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @return int
     */
    public function getState()
    {
        return $this->state;
    }

    /**
     * Output only. State of the task.
     *
     * Generated from protobuf field <code>.google.cloud.aiplatform.v1.PipelineTaskDetail.State state = 7 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @param int $var
     * @return $this
     */
    public function setState($var)
    {
        GPBUtil::checkEnum($var, \Google\Cloud\AIPlatform\V1\PipelineTaskDetail\State::class);
        $this->state = $var;

        return $this;
    }

    /**
     * Output only. The execution metadata of the task.
     *
     * Generated from protobuf field <code>.google.cloud.aiplatform.v1.Execution execution = 8 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @return \Google\Cloud\AIPlatform\V1\Execution|null
     */
    public function getExecution()
    {
        return $this->execution;
    }

    public function hasExecution()
    {
        return isset($this->execution);
    }

    public function clearExecution()
    {
        unset($this->execution);
    }

    /**
     * Output only. The execution metadata of the task.
     *
     * Generated from protobuf field <code>.google.cloud.aiplatform.v1.Execution execution = 8 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @param \Google\Cloud\AIPlatform\V1\Execution $var
     * @return $this
     */
    public function setExecution($var)
    {
        GPBUtil::checkMessage($var, \Google\Cloud\AIPlatform\V1\Execution::class);
        $this->execution = $var;

        return $this;
    }

    /**
     * Output only. The error that occurred during task execution.
     * Only populated when the task's state is FAILED or CANCELLED.
     *
     * Generated from protobuf field <code>.google.rpc.Status error = 9 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @return \Google\Rpc\Status|null
     */
    public function getError()
    {
        return $this->error;
    }

    public function hasError()
    {
        return isset($this->error);
    }

    public function clearError()
    {
        unset($this->error);
    }

    /**
     * Output only. The error that occurred during task execution.
     * Only populated when the task's state is FAILED or CANCELLED.
     *
     * Generated from protobuf field <code>.google.rpc.Status error = 9 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @param \Google\Rpc\Status $var
     * @return $this
     */
    public function setError($var)
    {
        GPBUtil::checkMessage($var, \Google\Rpc\Status::class);
        $this->error = $var;

        return $this;
    }

    /**
     * Output only. A list of task status. This field keeps a record of task status evolving
     * over time.
     *
     * Generated from protobuf field <code>repeated .google.cloud.aiplatform.v1.PipelineTaskDetail.PipelineTaskStatus pipeline_task_status = 13 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @return \Google\Protobuf\Internal\RepeatedField
     */
    public function getPipelineTaskStatus()
    {
        return $this->pipeline_task_status;
    }

    /**
     * Output only. A list of task status. This field keeps a record of task status evolving
     * over time.
     *
     * Generated from protobuf field <code>repeated .google.cloud.aiplatform.v1.PipelineTaskDetail.PipelineTaskStatus pipeline_task_status = 13 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @param \Google\Cloud\AIPlatform\V1\PipelineTaskDetail\PipelineTaskStatus[]|\Google\Protobuf\Internal\RepeatedField $var
     * @return $this
     */
    public function setPipelineTaskStatus($var)
    {
        $arr = GPBUtil::checkRepeatedField($var, \Google\Protobuf\Internal\GPBType::MESSAGE, \Google\Cloud\AIPlatform\V1\PipelineTaskDetail\PipelineTaskStatus::class);
        $this->pipeline_task_status = $arr;

        return $this;
    }

    /**
     * Output only. The runtime input artifacts of the task.
     *
     * Generated from protobuf field <code>map<string, .google.cloud.aiplatform.v1.PipelineTaskDetail.ArtifactList> inputs = 10 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @return \Google\Protobuf\Internal\MapField
     */
    public function getInputs()
    {
        return $this->inputs;
    }

    /**
     * Output only. The runtime input artifacts of the task.
     *
     * Generated from protobuf field <code>map<string, .google.cloud.aiplatform.v1.PipelineTaskDetail.ArtifactList> inputs = 10 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @param array|\Google\Protobuf\Internal\MapField $var
     * @return $this
     */
    public function setInputs($var)
    {
        $arr = GPBUtil::checkMapField($var, \Google\Protobuf\Internal\GPBType::STRING, \Google\Protobuf\Internal\GPBType::MESSAGE, \Google\Cloud\AIPlatform\V1\PipelineTaskDetail\ArtifactList::class);
        $this->inputs = $arr;

        return $this;
    }

    /**
     * Output only. The runtime output artifacts of the task.
     *
     * Generated from protobuf field <code>map<string, .google.cloud.aiplatform.v1.PipelineTaskDetail.ArtifactList> outputs = 11 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @return \Google\Protobuf\Internal\MapField
     */
    public function getOutputs()
    {
        return $this->outputs;
    }

    /**
     * Output only. The runtime output artifacts of the task.
     *
     * Generated from protobuf field <code>map<string, .google.cloud.aiplatform.v1.PipelineTaskDetail.ArtifactList> outputs = 11 [(.google.api.field_behavior) = OUTPUT_ONLY];</code>
     * @param array|\Google\Protobuf\Internal\MapField $var
     * @return $this
     */
    public function setOutputs($var)
    {
        $arr = GPBUtil::checkMapField($var, \Google\Protobuf\Internal\GPBType::STRING, \Google\Protobuf\Internal\GPBType::MESSAGE, \Google\Cloud\AIPlatform\V1\PipelineTaskDetail\ArtifactList::class);
        $this->outputs = $arr;

        return $this;
    }

}
